package com.druvu.jmxmp.it;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.NotificationListener;
import javax.management.ObjectName;
import javax.management.RuntimeMBeanException;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import org.testng.annotations.Test;

/**
 * Behavioral safety net: the basic round trip run over the only profile set this build accepts — {@code TLS SASL/PLAIN}
 * — with a mandatory {@link TestAuthenticator}. Attribute read, notification round trip, remote-exception propagation
 * and clean close, end to end through TLS + SASL/PLAIN. The authenticator must be invoked exactly once per connect.
 */
public class RoundTripIT {

    private Map<String, Object> serverEnv(TestAuthenticator auth) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        env.put(JMXConnectorServer.AUTHENTICATOR, auth);
        return env;
    }

    private Map<String, Object> clientEnv(String user, String pass) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        env.put(JMXConnector.CREDENTIALS, new String[] {user, pass});
        return env;
    }

    @Test
    public void tlsSaslRoundTrip() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("test:type=Echo");
        mbs.registerMBean(new Echo(), name);

        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, serverEnv(auth), mbs);
        server.start();
        try {
            JMXServiceURL address = server.getAddress();

            try (JMXConnector connector = JMXConnectorFactory.connect(address, clientEnv("admin", "s3cr3t"))) {
                var conn = connector.getMBeanServerConnection();

                assertEquals(conn.getAttribute(name, "Message"), "hello");

                CountDownLatch received = new CountDownLatch(1);
                AtomicInteger count = new AtomicInteger();
                NotificationListener listener = (n, handback) -> {
                    count.incrementAndGet();
                    received.countDown();
                };
                conn.addNotificationListener(name, listener, null, null);
                conn.invoke(name, "fire", new Object[0], new String[0]);
                assertTrue(received.await(5, TimeUnit.SECONDS), "no notification received within 5s");
                assertTrue(count.get() >= 1);
                conn.removeNotificationListener(name, listener);

                try {
                    conn.invoke(name, "boom", new Object[0], new String[0]);
                    throw new AssertionError("boom() did not throw");
                } catch (RuntimeMBeanException expected) {
                    assertEquals(expected.getTargetException().getClass(), IllegalStateException.class);
                    assertEquals(expected.getTargetException().getMessage(), "boom");
                }
            }
        } finally {
            server.stop();
        }

        assertEquals(auth.calls.get(), 1, "authenticator must be invoked exactly once");
    }

    @Test
    public void connectionFailureThrowsIOException() throws Exception {
        JMXServiceURL dead = new JMXServiceURL("jmxmp", "localhost", 2);
        try {
            JMXConnectorFactory.connect(dead, clientEnv("admin", "s3cr3t"));
            throw new AssertionError("connect to a dead address did not throw");
        } catch (IOException expected) {
            // expected
        }
    }
}
