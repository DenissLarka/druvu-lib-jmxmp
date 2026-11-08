package com.druvu.jmxmp.it;

import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;

import java.util.HashMap;
import java.util.Map;
import javax.management.MBeanServerFactory;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import org.testng.annotations.Test;

/**
 * A client acts as the user it authenticated as. SASL/PLAIN carries an optional authorization id; one that names
 * another user is refused, so that nobody takes over another user's grants with their own password.
 */
public class AuthorizationIdIT {

    private static final String AUTHORIZATION_ID = "jmx.remote.sasl.authorization.id";

    @Test
    public void anotherUsersAuthorizationIdIsRefused() throws Exception {
        assertNotNull(connectError("alice"), "svc must not act as alice");
    }

    @Test
    public void ownAuthorizationIdIsAccepted() throws Exception {
        assertNull(connectError("svc"), "an authorization id equal to the user is the user");
    }

    /** Connects as svc with the given authorization id; the exception the connect threw, or null when it connected. */
    private static Exception connectError(String authorizationId) throws Exception {
        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        senv.put(JMXConnectorServer.AUTHENTICATOR, new TestAuthenticator(Map.of("svc", "svc-pw", "alice", "alice-pw")));
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(
                new JMXServiceURL("jmxmp", "localhost", 0), senv, MBeanServerFactory.newMBeanServer());
        server.start();
        try {
            Map<String, Object> cenv = new HashMap<>();
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"svc", "svc-pw"});
            cenv.put(AUTHORIZATION_ID, authorizationId);
            try (JMXConnector connected = JMXConnectorFactory.connect(server.getAddress(), cenv)) {
                return null;
            } catch (Exception e) {
                return e;
            }
        } finally {
            server.stop();
        }
    }
}
