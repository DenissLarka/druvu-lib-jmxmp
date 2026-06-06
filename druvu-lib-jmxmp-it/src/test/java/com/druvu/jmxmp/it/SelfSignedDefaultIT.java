package com.druvu.jmxmp.it;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import com.druvu.jmxmp.shared.JmxmpServerSecurity;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import javax.management.MBeanServer;
import javax.management.MBeanServerConnection;
import javax.management.MBeanServerFactory;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.testng.annotations.Test;

/**
 * Zero-config TLS default: a server configured with {@code TLS SASL/PLAIN} + a
 * {@link javax.management.remote.JMXAuthenticator} but <b>no</b> {@code jmx.remote.tls.socket.factory} still starts —
 * druvu generates an ephemeral self-signed identity — and a client that trusts that certificate connects over
 * TLS+SASL/PLAIN. Proves "encrypted by default with zero server TLS configuration".
 */
public class SelfSignedDefaultIT {

    @Test
    public void serverWithoutTlsFactoryGetsEphemeralCertAndAcceptsClient() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put(JMXConnectorServer.AUTHENTICATOR, auth);
        // deliberately NO jmx.remote.tls.socket.factory → exercises the ephemeral self-signed default

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, senv, mbs);
        server.start();
        try {
            Map<String, Object> cenv = new HashMap<>();
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", trustAll().getSocketFactory());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", "s3cr3t"});

            try (JMXConnector c = JMXConnectorFactory.connect(server.getAddress(), cenv)) {
                MBeanServerConnection mbsc = c.getMBeanServerConnection();
                assertTrue(mbsc.getMBeanCount() > 0, "expected MBeans over the auto-TLS connection");
            }
        } finally {
            if (server.isActive()) {
                server.stop();
            }
        }
    }

    @Test
    public void builderWithoutTlsOmitsFactoryKeySoServerAutoGenerates() {
        Map<String, Object> env = JmxmpServerSecurity.builder()
                .authenticator(new TestAuthenticator(Map.of("admin", "s3cr3t")))
                .build();
        assertEquals(env.get("jmx.remote.profiles"), "TLS SASL/PLAIN");
        assertTrue(env.containsKey(javax.management.remote.JMXConnectorServer.AUTHENTICATOR));
        assertFalse(
                env.containsKey("jmx.remote.tls.socket.factory"),
                "no tls() ⇒ no factory key ⇒ server auto-generates an ephemeral self-signed cert");
    }

    @Test
    public void serverWithOnlyAuthenticatorDefaultsProfileAndCertThenAcceptsClient() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        Map<String, Object> senv = new HashMap<>();
        senv.put(javax.management.remote.JMXConnectorServer.AUTHENTICATOR, auth);
        // NO jmx.remote.profiles AND NO jmx.remote.tls.socket.factory — only the authenticator. The server must
        // default the profile to TLS SASL/PLAIN and auto-generate the ephemeral cert.

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, senv, mbs);
        server.start();
        try {
            Map<String, Object> cenv = new HashMap<>();
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", trustAll().getSocketFactory());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", "s3cr3t"});

            try (JMXConnector c = JMXConnectorFactory.connect(server.getAddress(), cenv)) {
                assertTrue(
                        c.getMBeanServerConnection().getMBeanCount() > 0,
                        "expected MBeans over the auto-secured connection");
            }
        } finally {
            if (server.isActive()) {
                server.stop();
            }
        }
    }

    /** A client {@link SSLContext} that trusts any certificate — the ephemeral server cert is unpinnable by design. */
    private static SSLContext trustAll() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(
                null,
                new TrustManager[] {
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                    }
                },
                null);
        return ctx;
    }
}
