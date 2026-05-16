package com.druvu.jmxmp.it;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import com.druvu.jmxmp.server.security.AllowAnyAuthenticator;
import java.io.IOException;
import java.security.Principal;
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
import javax.management.remote.jmxmp.JMXMPConnector;
import javax.management.remote.jmxmp.JMXMPConnectorServer;
import javax.security.auth.Subject;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Negative suite: the mandatory policy refuses every deployment shape other than {@code TLS SASL/PLAIN} with a
 * configured {@link javax.management.remote.JMXAuthenticator}, and no env key bypasses it.
 */
public class SecurityPolicyIT {

    private JMXServiceURL url() throws Exception {
        return new JMXServiceURL("jmxmp", "localhost", 0);
    }

    /** No jmx.remote.profiles set → IllegalArgumentException at construction. */
    @Test
    public void noProfilesRejectedAtConstruction() throws Exception {
        try {
            new JMXMPConnector(url(), new HashMap<>());
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("jmx.remote.profiles"), e.getMessage());
        }
    }

    @DataProvider(name = "wrongProfileSets")
    Object[][] wrongProfileSets() {
        return new Object[][] {
            {"", IllegalArgumentException.class}, // blank == not configured
            {"TLS", SecurityException.class}, // no auth
            {"SASL/PLAIN", SecurityException.class}, // no encryption
            {"TLS SASL/CRAM-MD5", SecurityException.class}, // wrong mechanism
            {"TLS SASL/DIGEST-MD5", SecurityException.class},
            {"TLS SASL/EXTERNAL", SecurityException.class},
            {"TLS SASL/GSSAPI", SecurityException.class},
            {"TLS SASL/PLAIN SASL/CRAM-MD5", SecurityException.class}, // extra entry
        };
    }

    /** Every wrong profile set is rejected at construction. */
    @Test(dataProvider = "wrongProfileSets")
    public void wrongProfileSetRejected(String spec, Class<? extends Throwable> expected) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", spec);
        try {
            new JMXMPConnector(url(), env);
            fail("expected " + expected.getSimpleName() + " for spec [" + spec + "]");
        } catch (Throwable t) {
            assertTrue(
                    expected.isInstance(t),
                    "spec [" + spec + "] threw " + t.getClass().getName() + " (" + t.getMessage() + "), expected "
                            + expected.getSimpleName());
        }
    }

    /** Server without any JMXAuthenticator → IllegalArgumentException at construction. */
    @Test
    public void serverWithoutAuthenticatorRejected() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        try {
            new JMXMPConnectorServer(url(), env, mbs);
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("JMXAuthenticator"), e.getMessage());
        }
    }

    /** AllowAnyAuthenticator without the ack token → SecurityException. */
    @Test
    public void allowAnyWithoutAckRejected() {
        try {
            new AllowAnyAuthenticator(new HashMap<>());
            fail("expected SecurityException");
        } catch (SecurityException e) {
            assertTrue(e.getMessage().contains(AllowAnyAuthenticator.ACK_KEY), e.getMessage());
        }
    }

    /** AllowAnyAuthenticator with ack constructs; user/anonymous principal. */
    @Test
    public void allowAnyWithAckBehaviour() {
        Map<String, Object> env = new HashMap<>();
        env.put(AllowAnyAuthenticator.ACK_KEY, AllowAnyAuthenticator.ACK_VALUE);
        AllowAnyAuthenticator a = new AllowAnyAuthenticator(env);

        Subject alice = a.authenticate(new String[] {"alice", "whatever"});
        assertTrue(hasPrincipalNamed(alice, "alice"));

        Subject anon = a.authenticate(new String[] {"", ""});
        assertTrue(hasPrincipalNamed(anon, "anonymous"));
    }

    /** Correct server, wrong SASL/PLAIN password → connect fails. */
    @Test
    public void wrongPasswordRejected() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        mbs.registerMBean(new Echo(), new ObjectName("test:type=Echo"));
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        senv.put(JMXConnectorServer.AUTHENTICATOR, auth);

        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url(), senv, mbs);
        server.start();
        try {
            Map<String, Object> cenv = new HashMap<>();
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", "WRONG"});
            try {
                JMXConnectorFactory.connect(server.getAddress(), cenv);
                fail("connect with wrong password must fail");
            } catch (IOException | SecurityException expected) {
                // expected: server rejects, sends HandshakeError, client throws
            }
        } finally {
            server.stop();
        }
    }

    private static boolean hasPrincipalNamed(Subject s, String name) {
        for (Principal p : s.getPrincipals()) {
            if (name.equals(p.getName())) {
                return true;
            }
        }
        return false;
    }
}
