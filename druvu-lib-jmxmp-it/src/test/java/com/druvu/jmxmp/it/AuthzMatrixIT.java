package com.druvu.jmxmp.it;

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

    /** ro: read-ish + coarse query/domains. ops: inherits ro + Cache invoke/set. alice→ops, svc-ro→ro. */
    private static JmxmpAccessControl matrixPolicy() {
        return JmxmpAccessControl.policy()
                .role("ro")
                .allow(JmxAction.GET_ATTRIBUTE, "*")
                .allow(JmxAction.GET_MBEAN_INFO, "*")
                .allow(JmxAction.QUERY)
                .allow(JmxAction.GET_DOMAINS)
                .role("ops")
                .inherit("ro")
                .allow(JmxAction.INVOKE, "com.acme:type=Cache,*")
                .allow(JmxAction.SET_ATTRIBUTE, "com.acme:type=Cache,*")
                .principal("alice")
                .grantedRoles("ops")
                .principal("svc-ro")
                .grantedRoles("ro")
                .build();
    }

    // ---- per-action + ObjectName scoping + inheritance ----------------------

    @Test
    public void inheritedReadAllowed() throws Exception {
        matrixPolicy()
                .checkAccess(subject("alice"), new JmxAccessRequest(JmxAction.GET_ATTRIBUTE, on("any:x=1"), "Foo"));
    }

    @Test
    public void scopedInvokeAllowedOnPattern() throws Exception {
        matrixPolicy()
                .checkAccess(
                        subject("alice"),
                        new JmxAccessRequest(JmxAction.INVOKE, on("com.acme:type=Cache,name=primary"), "evict"));
    }

    @Test
    public void scopedInvokeDeniedOffPattern() throws Exception {
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(
                                subject("alice"),
                                new JmxAccessRequest(JmxAction.INVOKE, on("other:type=Foo"), "evict")));
    }

    @Test
    public void defaultDenyForUngrantedAction() throws Exception {
        // svc-ro has only ro; SET_ATTRIBUTE is not in ro → strict default-deny.
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(
                                subject("svc-ro"),
                                new JmxAccessRequest(
                                        JmxAction.SET_ATTRIBUTE, on("com.acme:type=Cache,name=p"), "ttl")));
        // An action granted to nobody is denied even for alice.
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(
                                subject("alice"), new JmxAccessRequest(JmxAction.UNREGISTER_MBEAN, on("a:b=c"), null)));
    }

    @Test
    public void unknownPrincipalDenied() throws Exception {
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(
                                subject("nobody"), new JmxAccessRequest(JmxAction.GET_ATTRIBUTE, on("a:b=c"), "X")));
        // Empty subject (no principals) → denied.
        expectThrows(
                SecurityException.class,
                () -> matrixPolicy()
                        .checkAccess(new Subject(), new JmxAccessRequest(JmxAction.GET_ATTRIBUTE, on("a:b=c"), "X")));
    }

    @Test
    public void coarseQueryAndDomainsUntargeted() throws Exception {
        JmxmpAccessControl ac = matrixPolicy();
        ac.checkAccess(subject("svc-ro"), new JmxAccessRequest(JmxAction.QUERY, null, null));
        ac.checkAccess(subject("svc-ro"), new JmxAccessRequest(JmxAction.GET_DOMAINS, null, null));
    }

    @Test
    public void principalRoleUnion() throws Exception {
        // A subject carrying both svc-ro (ro) and alice (ops): union allows the ops-only SET_ATTRIBUTE.
        matrixPolicy()
                .checkAccess(
                        subject("svc-ro", "alice"),
                        new JmxAccessRequest(JmxAction.SET_ATTRIBUTE, on("com.acme:type=Cache,name=p"), "ttl"));
    }

    @Test
    public void allowAllPermitsEverything() throws Exception {
        JmxmpAccessControl.allowAll()
                .checkAccess(subject("anyone"), new JmxAccessRequest(JmxAction.UNREGISTER_MBEAN, on("x:y=z"), null));
        JmxmpAccessControl.allowAll()
                .checkAccess(new Subject(), new JmxAccessRequest(JmxAction.INVOKE, on("x:y=z"), "m"));
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
                () -> JmxmpAccessControl.policy().role("r").allow(JmxAction.GET_ATTRIBUTE, "not a valid object name"));
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
