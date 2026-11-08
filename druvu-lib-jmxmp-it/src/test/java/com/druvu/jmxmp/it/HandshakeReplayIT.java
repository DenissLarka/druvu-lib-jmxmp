package com.druvu.jmxmp.it;

import static org.testng.Assert.assertTrue;

import com.druvu.jmxmp.shared.SocketConnection;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.management.MBeanServerFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.message.HandshakeBeginMessage;
import javax.management.remote.message.HandshakeErrorMessage;
import javax.management.remote.message.Message;
import javax.management.remote.message.SASLMessage;
import javax.management.remote.message.TLSMessage;
import javax.net.ssl.SSLSocket;
import org.testng.annotations.Test;

/**
 * A profile runs once per connection. A client that is not ours runs TLS and SASL/PLAIN, then sends TLS again: the
 * server answers with a handshake error. Run again, TLS would hand the session its own Subject, which has no user.
 */
public class HandshakeReplayIT {

    @Test(timeOut = 60_000)
    public void aFinishedProfileCannotRunAgain() throws Exception {
        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        senv.put(JMXConnectorServer.AUTHENTICATOR, new TestAuthenticator(Map.of("admin", "s3cr3t")));
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(
                new JMXServiceURL("jmxmp", "localhost", 0), senv, MBeanServerFactory.newMBeanServer());
        server.start();
        JMXServiceURL address = server.getAddress();
        try (Socket plain = new Socket(address.getHost(), address.getPort())) {
            SocketConnection connection = new SocketConnection(plain);
            connection.connect(Map.of());
            assertTrue(connection.readMessage() instanceof HandshakeBeginMessage, "the server opens the handshake");

            connection.writeMessage(new TLSMessage(TLSMessage.READY));
            assertTrue(connection.readMessage() instanceof TLSMessage, "the server proceeds with TLS");
            SSLSocket tls = (SSLSocket)
                    TlsTestSupport.socketFactory().createSocket(plain, address.getHost(), address.getPort(), true);
            tls.setUseClientMode(true);
            tls.startHandshake();
            connection.setSocket(tls);

            // RFC 4616 SASL/PLAIN: authzid NUL authcid NUL password, here with an empty authzid
            byte[] credentials = "\0admin\0s3cr3t".getBytes(StandardCharsets.UTF_8);
            connection.writeMessage(new SASLMessage("PLAIN", SASLMessage.CONTINUE, credentials));
            assertTrue(connection.readMessage() instanceof SASLMessage, "the server accepts the credentials");

            connection.writeMessage(new TLSMessage(TLSMessage.READY));
            Message reply = connection.readMessage();
            assertTrue(reply instanceof HandshakeErrorMessage, "expected a handshake error, got " + reply);
        } finally {
            server.stop();
        }
    }
}
