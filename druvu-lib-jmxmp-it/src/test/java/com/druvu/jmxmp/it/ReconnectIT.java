package com.druvu.jmxmp.it;

import static org.testng.Assert.assertEquals;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.management.MBeanServer;
import javax.management.MBeanServerConnection;
import javax.management.MBeanServerDelegate;
import javax.management.MBeanServerFactory;
import javax.management.MBeanServerNotification;
import javax.management.NotificationListener;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import org.testng.annotations.Test;

/**
 * A client that loses its connection reconnects by itself and answers again. With a notification listener registered,
 * the reconnect re-adds the listener and waits for the server's answer, which only the new connection's reader can
 * deliver: the client must have a thread for that reader while the old one is still busy reconnecting.
 */
public class ReconnectIT {

    private static final long REQUEST_TIMEOUT_MILLIS = 10_000;

    @Test(timeOut = 120_000)
    public void reconnectsWithAListenerAfterTheConnectionDrops() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        JMXConnectorServer server = securedServer(mbs);
        server.start();
        JMXServiceURL address = server.getAddress();
        try (WireTap tap = new WireTap(address.getHost(), address.getPort());
                JMXConnector connector =
                        JMXConnectorFactory.connect(new JMXServiceURL("jmxmp", "localhost", tap.port()), clientEnv())) {
            MBeanServerConnection connection = connector.getMBeanServerConnection();
            BlockingQueue<ObjectName> registrations = new LinkedBlockingQueue<>();
            NotificationListener onRegistration = (notification, handback) -> {
                if (notification instanceof MBeanServerNotification registration
                        && MBeanServerNotification.REGISTRATION_NOTIFICATION.equals(registration.getType())) {
                    registrations.add(registration.getMBeanName());
                }
            };
            connection.addNotificationListener(MBeanServerDelegate.DELEGATE_NAME, onRegistration, null, null);
            ObjectName before = new ObjectName("test:type=Echo,name=beforeDrop");
            mbs.registerMBean(new Echo(), before);
            assertEquals(registrations.poll(30, TimeUnit.SECONDS), before, "the listener works before the drop");
            int mbeansBefore = connection.getMBeanCount();

            tap.dropConnections();

            assertEquals(firstAnswerWithin(connection, 60), mbeansBefore, "the client works again after reconnecting");
        } finally {
            server.stop();
        }
    }

    /** Asks for the MBean count until the reconnected client answers; requests fail while it reconnects. */
    private static int firstAnswerWithin(MBeanServerConnection connection, int seconds) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
        IOException last = null;
        while (System.nanoTime() < deadline) {
            try {
                return connection.getMBeanCount();
            } catch (IOException reconnecting) {
                last = reconnecting;
                Thread.sleep(200);
            }
        }
        throw new AssertionError("no answer within " + seconds + " s after the connection dropped", last);
    }

    private static Map<String, Object> clientEnv() throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        env.put(JMXConnector.CREDENTIALS, new String[] {"admin", "s3cr3t"});
        // A request that gets no answer fails after this long instead of waiting forever.
        env.put("jmx.remote.x.request.timeout", REQUEST_TIMEOUT_MILLIS);
        return env;
    }

    private static JMXConnectorServer securedServer(MBeanServer mbs) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        env.put(JMXConnectorServer.AUTHENTICATOR, new TestAuthenticator(Map.of("admin", "s3cr3t")));
        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        return JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbs);
    }
}
