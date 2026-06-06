package com.druvu.jmxmp.it;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

import com.druvu.jmxmp.shared.JmxAction;
import com.druvu.jmxmp.shared.JmxmpAccessControl;
import java.util.HashMap;
import java.util.Map;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import org.testng.annotations.Test;

/**
 * Subject-propagation migration tests (PLAN-2.0.0 §8 item 3.2), including the <strong>permanent JDK-25 fail-open
 * regression guard</strong>.
 *
 * <p>Context: OpenDMK (and the four republications) read identity via {@code Subject.getSubject(
 * AccessController.getContext())}, which is <em>always {@code null}</em> on JDK&nbsp;25 (JEP&nbsp;486, no Security
 * Manager); the bundled file access controller then treated {@code null} as "security not enabled ⇒ allow everything" —
 * a silent authorization bypass. This fork reads identity via {@code Subject.current()} (propagated by
 * {@code ServerIntermediary}'s {@code Subject.callAs}) and fails closed on an absent subject.
 *
 * <p>These tests run end-to-end over real TLS + SASL/PLAIN and must pass on <strong>both JDK&nbsp;21 and
 * JDK&nbsp;25</strong>. Run as a permanent suite member they make the §2 bypass un-reintroducible: if identity
 * propagation regressed, the authenticated principal would not be visible and
 * {@link #identityDrivesPolicyMatch_grantSeenAsAdmin} / {@link #mbeanObservesAuthenticatedCaller} would fail; if a
 * configured control ever fell back to allow-all, {@link #failOpenRegressionGuard_configuredPolicyDeniesUngranted}
 * would fail.
 */
public class SubjectMigrationIT {

    private Map<String, Object> serverEnv(TestAuthenticator auth, JmxmpAccessControl ac) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        env.put(JMXConnectorServer.AUTHENTICATOR, auth);
        if (ac != null) {
            env.put(JmxmpAccessControl.ENV_KEY, ac);
        }
        return env;
    }

    private Map<String, Object> clientEnv(String user, String pass) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        env.put(JMXConnector.CREDENTIALS, new String[] {user, pass});
        return env;
    }

    /**
     * The authenticated SASL subject is visible to MBean code via {@code Subject.current()} (not null, correct name).
     */
    @Test
    public void mbeanObservesAuthenticatedCaller() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("test:type=Caller");
        mbs.registerMBean(new Caller(), name);
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, serverEnv(auth, null), mbs);
        server.start();
        try (JMXConnector c = JMXConnectorFactory.connect(server.getAddress(), clientEnv("admin", "s3cr3t"))) {
            Object who = c.getMBeanServerConnection().invoke(name, "whoAmI", new Object[0], new String[0]);
            // Pre-migration on JDK 25 this would be "<none>" (Subject.getSubject(acc) == null) — the bypass.
            assertEquals(who, "admin", "MBean must observe the authenticated caller via Subject.current()");
        } finally {
            server.stop();
        }
    }

    /** A configured control sees the real authenticated principal and a matching grant succeeds (not blanket-deny). */
    @Test
    public void identityDrivesPolicyMatch_grantSeenAsAdmin() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("test:type=Echo");
        mbs.registerMBean(new Echo(), name);
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        JmxmpAccessControl ac = JmxmpAccessControl.policy()
                .role("r")
                .allow(JmxAction.READ, "*")
                .principal("admin")
                .grantedRoles("r")
                .build();

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, serverEnv(auth, ac), mbs);
        server.start();
        try (JMXConnector c = JMXConnectorFactory.connect(server.getAddress(), clientEnv("admin", "s3cr3t"))) {
            // Succeeds ONLY because Subject.current() carried principal "admin" so the "admin"→"r" grant matched.
            assertEquals(c.getMBeanServerConnection().getAttribute(name, "Message"), "hello");
        } finally {
            server.stop();
        }
    }

    /**
     * THE PERMANENT FAIL-OPEN REGRESSION GUARD. A real authenticated subject + a configured control that does not grant
     * the operation must be DENIED. If the §2 JDK-25 bypass ever reappears (absent identity ⇒ allow-all), this
     * ungranted call would succeed and this test would fail.
     */
    @Test
    public void failOpenRegressionGuard_configuredPolicyDeniesUngranted() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("test:type=Echo");
        mbs.registerMBean(new Echo(), name);
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        // admin is authenticated and mapped to a role, but the role does NOT grant READ (only INVOKE).
        JmxmpAccessControl ac = JmxmpAccessControl.policy()
                .role("r")
                .allow(JmxAction.INVOKE, "*")
                .principal("admin")
                .grantedRoles("r")
                .build();

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, serverEnv(auth, ac), mbs);
        server.start();
        try (JMXConnector c = JMXConnectorFactory.connect(server.getAddress(), clientEnv("admin", "s3cr3t"))) {
            var conn = c.getMBeanServerConnection();
            Throwable t = expectThrows(Exception.class, () -> conn.getAttribute(name, "Message"));
            String chain = t.toString() + (t.getCause() != null ? " / " + t.getCause() : "");
            assertTrue(
                    chain.contains("Access denied") || t instanceof SecurityException,
                    "ungranted op must be denied for an authenticated subject (no fail-open); got: " + chain);
        } finally {
            server.stop();
        }
    }
}
