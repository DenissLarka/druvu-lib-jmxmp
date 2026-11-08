package com.druvu.jmxmp.it;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import com.druvu.jmxmp.ClientProfilePolicy;
import com.druvu.jmxmp.SelectProfiles;
import com.druvu.jmxmp.internal.SocketConnection;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.management.MBeanServerFactory;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.message.HandshakeBeginMessage;
import javax.management.remote.message.HandshakeErrorMessage;
import javax.management.remote.message.Message;
import javax.management.remote.message.SASLMessage;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Guards the invariant that the client enforces its transport policy <b>before</b> any credential-bearing profile runs:
 * a policy violation on the negotiated profile set must abort the handshake before SASL/PLAIN transmits the password.
 *
 * <p>Regression target: a custom {@link SelectProfiles} selector (as JConsoleBooster installs) that downgrades to the
 * server's offer can drop TLS; if the profile policy is only checked <em>after</em> the profile loop, the password has
 * already crossed a plaintext wire. The authenticator's call count is the wire-level probe — it is invoked only if the
 * SASL/PLAIN exchange actually reached the server.
 *
 * <p>The same holds for the order of the profiles: the client runs them in list order, so {@code SASL/PLAIN TLS} keeps
 * the right set and still sends the password before TLS starts. TLS runs first on both sides: the client refuses such a
 * list under every policy (a {@link WireTap} proves nothing crossed in clear), and the server refuses a SASL message
 * that arrives before TLS.
 */
public class PlaintextCredentialGuardIT {

    private static final String PASSWORD = "wire-tap-s3cr3t";

    @Test
    public void policyRejectsDowngradeBeforeCredentialsReachTheServer() throws Exception {
        // A normal secured server; the DOWNGRADE is injected on the client via a custom selector, exactly as a
        // TLS-strip would surface (a server of this library refuses to run plaintext at all).
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", PASSWORD));
        JMXConnectorServer server = securedServer(auth);
        server.start();
        JMXServiceURL address = server.getAddress();
        try (WireTap tap = new WireTap(address.getHost(), address.getPort())) {
            Map<String, Object> cenv = new HashMap<>();
            // Passes the construction-time spec check, then the selector downgrades the chosen set to plaintext.
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
            SelectProfiles downgrade = (env, serverProfiles) -> env.put("jmx.remote.profiles", "SASL/PLAIN");
            cenv.put("com.sun.jmx.remote.profile.selector", downgrade);
            cenv.put(ClientProfilePolicy.ENV_KEY, ClientProfilePolicy.mandatoryTlsSasl());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", PASSWORD});

            Exception refused = connectError(new JMXServiceURL("jmxmp", "localhost", tap.port()), cenv);

            // The pre-loop policy check aborts before the SASL/PLAIN profile runs: the password never leaves the
            // client. The server refuses SASL before TLS too, so only the wire can tell the client's check apart.
            assertFalse(tap.sawInClear(PASSWORD), "the client sent the password over the downgraded connection");
            assertNotNull(refused, "the client must refuse the downgrade");
            assertEquals(auth.calls.get(), 0, "the authenticator must never be reached");
        } finally {
            server.stop();
        }
    }

    @DataProvider
    Object[][] clientPolicies() {
        return new Object[][] {{ClientProfilePolicy.mandatoryTlsSasl()}, {ClientProfilePolicy.unrestricted()}};
    }

    /** A selector that puts SASL before TLS keeps the right set; the client still refuses before SASL runs. */
    @Test(dataProvider = "clientPolicies")
    public void clientRefusesSaslBeforeTls(ClientProfilePolicy policy) throws Exception {
        JMXConnectorServer server = securedServer(new TestAuthenticator(Map.of("admin", PASSWORD)));
        server.start();
        JMXServiceURL address = server.getAddress();
        try (WireTap tap = new WireTap(address.getHost(), address.getPort())) {
            Map<String, Object> cenv = new HashMap<>();
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
            SelectProfiles saslFirst = (env, serverProfiles) -> env.put("jmx.remote.profiles", "SASL/PLAIN TLS");
            cenv.put("com.sun.jmx.remote.profile.selector", saslFirst);
            cenv.put(ClientProfilePolicy.ENV_KEY, policy);
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", PASSWORD});

            Exception refused = connectError(new JMXServiceURL("jmxmp", "localhost", tap.port()), cenv);

            assertFalse(tap.sawInClear(PASSWORD), "the password crossed the wire in clear, before TLS");
            assertNotNull(refused, "the client must refuse to run SASL before TLS");
        } finally {
            server.stop();
        }
    }

    /** A client that is not ours sends SASL/PLAIN first: a handshake error, and the authenticator never runs. */
    @Test
    public void serverRefusesSaslBeforeTls() throws Exception {
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", PASSWORD));
        JMXConnectorServer server = securedServer(auth);
        server.start();
        JMXServiceURL address = server.getAddress();
        try (Socket socket = new Socket(address.getHost(), address.getPort())) {
            SocketConnection connection = new SocketConnection(socket);
            connection.connect(Map.of());
            assertTrue(connection.readMessage() instanceof HandshakeBeginMessage, "the server opens the handshake");

            // RFC 4616 SASL/PLAIN: authzid NUL authcid NUL password, here with an empty authzid
            byte[] credentials = ("\0admin\0" + PASSWORD).getBytes(StandardCharsets.UTF_8);
            connection.writeMessage(new SASLMessage("PLAIN", SASLMessage.CONTINUE, credentials));

            Message reply = connection.readMessage();
            assertTrue(reply instanceof HandshakeErrorMessage, "expected a handshake error, got " + reply);
            assertEquals(auth.calls.get(), 0, "the authenticator must never see a credential sent before TLS");
        } finally {
            server.stop();
        }
    }

    private static JMXConnectorServer securedServer(TestAuthenticator auth) throws Exception {
        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        senv.put(JMXConnectorServer.AUTHENTICATOR, auth);
        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        return JMXConnectorServerFactory.newJMXConnectorServer(url, senv, MBeanServerFactory.newMBeanServer());
    }

    /** Connects and closes again; the exception the connect threw, or {@code null} when it connected. */
    private static Exception connectError(JMXServiceURL url, Map<String, Object> env) {
        try (JMXConnector connected = JMXConnectorFactory.connect(url, env)) {
            return null;
        } catch (Exception e) {
            return e;
        }
    }
}
