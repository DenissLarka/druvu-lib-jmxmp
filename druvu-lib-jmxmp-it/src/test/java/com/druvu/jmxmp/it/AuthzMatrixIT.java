package com.druvu.jmxmp.it;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

import com.druvu.jmxmp.shared.JmxAccessRequest;
import com.druvu.jmxmp.shared.JmxAction;
import com.druvu.jmxmp.shared.JmxmpAccessControl;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXPrincipal;
import javax.management.remote.JMXProviderException;
import javax.management.remote.JMXServiceURL;
import javax.security.auth.Subject;
import org.testng.annotations.Test;

/**
 * Authorization matrix (PLAN-2.0.0 §8 item 3.1). The bulk runs the built-in {@link JmxmpAccessControl#policy()} RBAC
 * directly (deterministic, no socket); two integration cases use the reliable classpath TLS+SASL harness: the
 * non-typed-{@code ENV_KEY} fail-closed-at-start guarantee and the delegation-rejection guarantee.
 */
public class AuthzMatrixIT {

    private static Subject subject(String... principals) {
        Set<java.security.Principal> ps = new LinkedHashSet<>();
        for (String p : principals) {
            ps.add(new JMXPrincipal(p));
        }
        return new Subject(true, ps, Set.of(), Set.of());
    }

    private static ObjectName on(String s) throws Exception {
        return new ObjectName(s);
    }

    /** ro: targeted + untargeted READ. ops: inherits ro + Cache invoke/write. alice→ops, svc-ro→ro. */
    private static JmxmpAccessControl matrixPolicy() {
        return JmxmpAccessControl.policy()
                .role("ro")
                .allow(JmxAction.READ, "*")
                .allow(JmxAction.READ)
                .role("ops")
                .inherit("ro")
                .allow(JmxAction.INVOKE, "com.acme:type=Cache,*")
                .allow(JmxAction.WRITE, "com.acme:type=Cache,*")
                .principal("alice")
                .grantedRoles("ops")
                .principal("svc-ro")
                .grantedRoles("ro")
                .build();
    }

    // ---- per-action + ObjectName scoping + inheritance ----------------------

    @Test
    public void inheritedReadAllowed() throws Exception {
        matrixPolicy().checkAccess(subject("alice"), new JmxAccessRequest(JmxAction.READ, on("any:x=1")));
    }

    @Test
    public void scopedInvokeAllowedOnPattern() throws Exception {
        matrixPolicy()
                .checkAccess(
                        subject("alice"),
                        new JmxAccessRequest(JmxAction.INVOKE, on("com.acme:type=Cache,name=primary")));
    }

    @Test
    public void scopedInvokeDeniedOffPattern() throws Exception {
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(subject("alice"), new JmxAccessRequest(JmxAction.INVOKE, on("other:type=Foo"))));
    }

    @Test
    public void defaultDenyForUngrantedAction() throws Exception {
        // svc-ro has only ro; WRITE is not in ro → strict default-deny.
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(
                                subject("svc-ro"),
                                new JmxAccessRequest(JmxAction.WRITE, on("com.acme:type=Cache,name=p"))));
        // An action granted to no role (NOTIFY) is denied even for the privileged alice.
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(subject("alice"), new JmxAccessRequest(JmxAction.NOTIFY, on("a:b=c"))));
    }

    @Test
    public void unknownPrincipalDenied() throws Exception {
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy().checkAccess(subject("nobody"), new JmxAccessRequest(JmxAction.READ, on("a:b=c"))));
        // Empty subject (no principals) → denied.
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy().checkAccess(new Subject(), new JmxAccessRequest(JmxAction.READ, on("a:b=c"))));
    }

    @Test
    public void untargetedReadAllowed() throws Exception {
        // queryNames/getDomains arrive as an untargeted READ; ro grants allow(READ).
        matrixPolicy().checkAccess(subject("svc-ro"), new JmxAccessRequest(JmxAction.READ, null));
    }

    @Test
    public void principalRoleUnion() throws Exception {
        // A subject carrying both svc-ro (ro) and alice (ops): union allows the ops-only WRITE.
        matrixPolicy()
                .checkAccess(
                        subject("svc-ro", "alice"),
                        new JmxAccessRequest(JmxAction.WRITE, on("com.acme:type=Cache,name=p")));
    }

    @Test
    public void allowAllPermitsAllVerbs() throws Exception {
        JmxmpAccessControl ac = JmxmpAccessControl.allowAll();
        ac.checkAccess(subject("anyone"), new JmxAccessRequest(JmxAction.READ, on("x:y=z")));
        ac.checkAccess(subject("anyone"), new JmxAccessRequest(JmxAction.WRITE, on("x:y=z")));
        ac.checkAccess(subject("anyone"), new JmxAccessRequest(JmxAction.INVOKE, on("x:y=z")));
        ac.checkAccess(new Subject(), new JmxAccessRequest(JmxAction.NOTIFY, on("x:y=z")));
    }

    // ---- builder fail-fast configuration validation -------------------------

    @Test
    public void inheritUnknownRoleRejectedAtBuild() {
        expectThrows(
                IllegalStateException.class,
                () -> JmxmpAccessControl.policy().role("a").inherit("ghost").build());
    }

    @Test
    public void inheritanceCycleRejectedAtBuild() {
        expectThrows(
                IllegalStateException.class,
                () -> JmxmpAccessControl.policy()
                        .role("a")
                        .inherit("b")
                        .role("b")
                        .inherit("a")
                        .build());
    }

    @Test
    public void grantedRolesBeforePrincipalRejected() {
        expectThrows(
                IllegalStateException.class,
                () -> JmxmpAccessControl.policy().role("r").grantedRoles("r"));
    }

    @Test
    public void malformedPatternRejectedEagerly() {
        expectThrows(
                IllegalArgumentException.class,
                () -> JmxmpAccessControl.policy().role("r").allow(JmxAction.READ, "not a valid object name"));
    }

    // ---- integration: non-typed ENV_KEY fails closed at server start --------

    @Test
    public void nonTypedAccessControlValueFailsClosedAtStart() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        env.put(JMXConnectorServer.AUTHENTICATOR, auth);
        env.put(JmxmpAccessControl.ENV_KEY, "not-a-JmxmpAccessControl"); // a String, e.g. from -D/props

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbs);
        SecurityException ex = expectThrows(SecurityException.class, server::start);
        assertTrue(ex.getMessage().contains(JmxmpAccessControl.ENV_KEY), ex.getMessage());
        if (server.isActive()) {
            server.stop();
        }
    }

    // ---- integration: a plaintext (unsecured) server config fails at the factory with a clear, non-masked reason ----

    @Test
    public void plaintextServerConfigFailsWithClearProviderExceptionNotMaskedProtocol() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        // A plaintext console: no jmx.remote.profiles, no JMXAuthenticator — the dominant legacy JMXMP server shape.
        Map<String, Object> env = new HashMap<>();
        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);

        // The mandatory server gate must surface a JMXProviderException that names the required profiles, NOT the JDK's
        // misleading "Unsupported protocol: jmxmp" (which the factory emits when a provider throws a plain runtime
        // exception, and which reads as if the provider were absent from the classpath).
        JMXProviderException ex = expectThrows(
                JMXProviderException.class, () -> JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbs));
        assertTrue(ex.getMessage().contains("TLS SASL/PLAIN"), ex.getMessage());
        assertFalse(ex.getMessage().contains("Unsupported protocol"), ex.getMessage());
    }

    // ---- integration: remote MBean lifecycle is denied over the wire, even under allowAll() ----

    @Test
    public void lifecycleDeniedOverWireEvenUnderAllowAll() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        senv.put(JMXConnectorServer.AUTHENTICATOR, auth);
        // Authorization explicitly OFF — yet lifecycle must still be denied.
        senv.put(JmxmpAccessControl.ENV_KEY, JmxmpAccessControl.allowAll());

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, senv, mbs);
        server.start();
        try {
            Map<String, Object> cenv = new HashMap<>();
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", "s3cr3t"});

            try (JMXConnector connector = JMXConnectorFactory.connect(server.getAddress(), cenv)) {
                var conn = connector.getMBeanServerConnection();

                // A benign read succeeds (allowAll permits READ) — proving the server is otherwise functional.
                assertTrue(conn.getMBeanCount() >= 0);

                // createMBean is wire-reachable (CREATE_MBEAN opcode) but permanently denied.
                Throwable create = expectThrows(
                        Exception.class,
                        () -> conn.createMBean("javax.management.timer.Timer", new ObjectName("evil:type=Timer")));
                assertTrue(chain(create).contains("permanently disabled"), chain(create));

                // unregisterMBean likewise (UNREGISTER_MBEAN opcode).
                Throwable unreg =
                        expectThrows(Exception.class, () -> conn.unregisterMBean(new ObjectName("evil:type=Timer")));
                assertTrue(chain(unreg).contains("permanently disabled"), chain(unreg));
            }
        } finally {
            server.stop();
        }
    }

    private static String chain(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c).append(" / ");
        }
        return sb.toString();
    }

    // ---- integration: a request carrying a delegation subject is rejected ---

    @Test
    @SuppressWarnings("removal") // getMBeanServerConnection(Subject) is exercised on purpose: prove it is rejected
    public void delegationRequestRejectedFailClosed() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("test:type=Echo");
        mbs.registerMBean(new Echo(), name);
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        senv.put(JMXConnectorServer.AUTHENTICATOR, auth);

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, senv, mbs);
        server.start();
        try {
            Map<String, Object> cenv = new HashMap<>();
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", "s3cr3t"});

            try (JMXConnector connector = JMXConnectorFactory.connect(server.getAddress(), cenv)) {
                Subject delegation = subject("someone-else");
                var conn = connector.getMBeanServerConnection(delegation);
                Throwable t = expectThrows(Exception.class, () -> conn.getAttribute(name, "Message"));
                String chain = t.toString() + (t.getCause() != null ? " / " + t.getCause() : "");
                assertTrue(
                        chain.contains("Subject delegation is not supported"),
                        "expected delegation rejection, got: " + chain);
            }
        } finally {
            server.stop();
        }
    }
}
