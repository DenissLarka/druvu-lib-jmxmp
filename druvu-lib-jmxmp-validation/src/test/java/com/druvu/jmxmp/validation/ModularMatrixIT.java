/*
 * Validation & compatibility matrix, run on the JPMS MODULE PATH.
 *
 * The mere fact this class loads and runs while its test module-info declares
 * `requires com.druvu.jmxmp.client; requires com.druvu.jmxmp.server;` is the
 * split-package-freedom proof: a leaked package across the
 * client/server/common seam would fail module resolution before any test body
 * executes.
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import com.druvu.jmxmp.spi.GenericConnectorEngineProvider;
import com.druvu.jmxmp.spi.GenericConnectorServerEngineProvider;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.NotificationListener;
import javax.management.ObjectName;
import javax.management.RuntimeMBeanException;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorProvider;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXConnectorServerProvider;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.jmxmp.JMXMPConnector;
import org.testng.annotations.Test;

public class ModularMatrixIT {

    private Map<String, Object> serverEnv(Auth auth) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsSupport.socketFactory());
        env.put(JMXConnectorServer.AUTHENTICATOR, auth);
        return env;
    }

    private Map<String, Object> clientEnv(String user, String pass) throws Exception {
        Map<String, Object> env = new HashMap<>();
        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.tls.socket.factory", TlsSupport.socketFactory());
        env.put(JMXConnector.CREDENTIALS, new String[] {user, pass});
        return env;
    }

    private JMXConnectorServer startServer(MBeanServer mbs, Auth auth) throws Exception {
        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, serverEnv(auth), mbs);
        server.start();
        return server;
    }

    /** Both-sides modular loopback over TLS SASL/PLAIN. */
    @Test
    public void bothSidesModularRoundTrip() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("validation:type=Counter");
        mbs.registerMBean(new Counter(), name);
        Auth auth = new Auth(Map.of("admin", "s3cr3t"));

        JMXConnectorServer server = startServer(mbs, auth);
        try {
            try (JMXConnector connector =
                    JMXConnectorFactory.connect(server.getAddress(), clientEnv("admin", "s3cr3t"))) {
                var conn = connector.getMBeanServerConnection();
                assertEquals(conn.getAttribute(name, "Message"), "hello");

                CountDownLatch got = new CountDownLatch(1);
                NotificationListener l = (n, h) -> got.countDown();
                conn.addNotificationListener(name, l, null, null);
                conn.invoke(name, "burst", new Object[] {1}, new String[] {"int"});
                assertTrue(got.await(5, TimeUnit.SECONDS), "no notification within 5s");
                conn.removeNotificationListener(name, l);

                try {
                    conn.invoke(name, "boom", new Object[0], new String[0]);
                    throw new AssertionError("boom() did not throw");
                } catch (RuntimeMBeanException expected) {
                    assertEquals(expected.getTargetException().getClass(), IllegalStateException.class);
                }
            }
        } finally {
            server.stop();
        }
        assertEquals(auth.calls.get(), 1, "authenticator must be invoked exactly once per connect");
    }

    /** 1000 notifications, all received, strictly in sequence order. */
    @Test
    public void notificationLoadOrdered1000() throws Exception {
        final int n = 1000;
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("validation:type=Counter");
        mbs.registerMBean(new Counter(), name);
        Auth auth = new Auth(Map.of("admin", "s3cr3t"));

        JMXConnectorServer server = startServer(mbs, auth);
        try {
            try (JMXConnector connector =
                    JMXConnectorFactory.connect(server.getAddress(), clientEnv("admin", "s3cr3t"))) {
                var conn = connector.getMBeanServerConnection();
                List<Long> seqs = new CopyOnWriteArrayList<>();
                CountDownLatch all = new CountDownLatch(n);
                conn.addNotificationListener(
                        name,
                        (notif, h) -> {
                            seqs.add(notif.getSequenceNumber());
                            all.countDown();
                        },
                        null,
                        null);
                conn.invoke(name, "burst", new Object[] {n}, new String[] {"int"});
                assertTrue(all.await(30, TimeUnit.SECONDS), "only " + seqs.size() + "/" + n + " notifications in 30s");

                assertEquals(seqs.size(), n);
                List<Long> expected = new ArrayList<>(n);
                for (long i = 1; i <= n; i++) {
                    expected.add(i);
                }
                assertEquals(seqs, expected, "notifications must arrive in strict sequence order");
            }
        } finally {
            server.stop();
        }
    }

    /**
     * Serialization stability. {@code JMXMPConnector.env} is {@code transient}; the address survives a
     * serialize/deserialize round trip and the reconstituted connector connects and yields a valid connection id.
     */
    @Test
    public void connectorSerializationStability() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        ObjectName name = new ObjectName("validation:type=Counter");
        mbs.registerMBean(new Counter(), name);
        Auth auth = new Auth(Map.of("admin", "s3cr3t"));

        JMXConnectorServer server = startServer(mbs, auth);
        try {
            JMXMPConnector original = new JMXMPConnector(server.getAddress());

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                oos.writeObject(original);
            }
            JMXMPConnector restored;
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
                restored = (JMXMPConnector) ois.readObject();
            }
            assertNotNull(restored);
            assertEquals(restored.toString(), original.toString(), "serialized address must survive");

            restored.connect(clientEnv("admin", "s3cr3t"));
            try {
                String id = restored.getConnectionId();
                assertNotNull(id, "deserialized+connected connector must yield a connection id");
                assertTrue(id.contains("jmxmp"), "connection id should carry the jmxmp protocol: " + id);
                assertEquals(restored.getMBeanServerConnection().getAttribute(name, "Message"), "hello");
            } finally {
                restored.close();
            }
        } finally {
            server.stop();
        }
    }

    /**
     * On the module path the engine + protocol providers resolve via {@link ServiceLoader} from the renamed
     * {@code com.druvu.jmxmp.{client,server}.*} packages, with no {@code jmx.remote.profile.provider.pkgs} override.
     * (The negative "common-only → helpful error" graph is asserted statically by module-graphs.sh.)
     */
    @Test
    public void providersResolveFromRenamedPackages() {
        var clientEngine =
                ServiceLoader.load(GenericConnectorEngineProvider.class).findFirst();
        assertTrue(clientEngine.isPresent(), "client GenericConnectorEngineProvider not discovered");
        assertTrue(
                clientEngine.get().getClass().getName().startsWith("com.druvu.jmxmp.client."),
                clientEngine.get().getClass().getName());

        var serverEngine =
                ServiceLoader.load(GenericConnectorServerEngineProvider.class).findFirst();
        assertTrue(serverEngine.isPresent(), "server GenericConnectorServerEngineProvider not discovered");
        assertTrue(
                serverEngine.get().getClass().getName().startsWith("com.druvu.jmxmp.server."),
                serverEngine.get().getClass().getName());

        boolean clientProto = ServiceLoader.load(JMXConnectorProvider.class).stream()
                .anyMatch(p -> p.type().getName().startsWith("com.druvu.jmxmp.client.protocol.jmxmp."));
        assertTrue(clientProto, "JMXConnectorProvider not from com.druvu.jmxmp.client.protocol.jmxmp");

        boolean serverProto = ServiceLoader.load(JMXConnectorServerProvider.class).stream()
                .anyMatch(p -> p.type().getName().startsWith("com.druvu.jmxmp.server.protocol.jmxmp."));
        assertTrue(serverProto, "JMXConnectorServerProvider not from com.druvu.jmxmp.server.protocol.jmxmp");
    }
}
