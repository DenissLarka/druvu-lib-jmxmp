/*
 * GenericConnectorServerEngineImpl.java
 *
 * Server-side engine extracted from the OpenDMK GenericConnectorServer in the
 * com.druvu fork (2.0). Behaviour is preserved from the original Sun code
 * (Copyright (c) 2007 Sun Microsystems, Inc.); the facade/engine split,
 * connection-notification-via-callback wiring and package moves are fork
 * changes. Dual-licensed: GPL v2 only with the Classpath exception, or
 * CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.server.generic;

import com.druvu.jmxmp.shared.ArrayNotificationBuffer;
import com.druvu.jmxmp.shared.DefaultConfig;
import com.druvu.jmxmp.shared.JmxmpAccessControl;
import com.druvu.jmxmp.shared.NotificationBuffer;
import com.druvu.jmxmp.shared.ObjectWrappingImpl;
import com.druvu.jmxmp.shared.ServerSynchroMessageConnection;
import com.druvu.jmxmp.shared.SynchroMessageConnectionServer;
import com.druvu.jmxmp.spi.GenericConnectorServerEngine;
import com.druvu.jmxmp.spi.ServerConnectionCallback;
import com.druvu.jmxmp.util.ClassLogger;
import com.druvu.jmxmp.util.EnvHelp;
import com.druvu.jmxmp.util.ThreadService;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.MBeanServerForwarder;
import javax.management.remote.generic.MessageConnectionServer;
import javax.management.remote.generic.ObjectWrapping;
import javax.security.auth.Subject;

/**
 * Implementation half of the {@code javax.management.remote.generic .GenericConnectorServer} facade. Holds the accept
 * loop, client list and transport server; the facade keeps the mandatory-security gate and the
 * {@code JMXConnectorServer} connection-notification machinery (fed via {@link ServerConnectionCallback}).
 */
public final class GenericConnectorServerEngineImpl implements GenericConnectorServerEngine {

    // env keys — inlined to avoid an engine -> facade compile edge.
    private static final String OBJECT_WRAPPING = "jmx.remote.object.wrapping";
    private static final String MESSAGE_CONNECTION_SERVER = "jmx.remote.message.connection.server";

    private static final int CREATED = 0;
    private static final int STARTED = 1;
    private static final int STOPPED = 2;

    private final JMXConnectorServer facade;
    private final ServerConnectionCallback callback;
    private final Map env;
    private final long connectingTimeout;

    private Receiver receiver;
    private SynchroMessageConnectionServer sMsgServer;
    private ObjectWrapping objectWrapping;
    private ClassLoader defaultClassLoader = null;
    private final ThreadService threads = new ThreadService(0, 10);
    private final ArrayList clientList = new ArrayList();
    private int state = CREATED;
    private final int[] lock = new int[0];
    private NotificationBuffer notifBuffer;
    private final Timer cancelConnecting = new Timer(true);

    private static final ClassLogger logger =
            new ClassLogger("com.druvu.jmxmp.server.generic", "GenericConnectorServerEngineImpl");

    public GenericConnectorServerEngineImpl(
            JMXConnectorServer facade,
            ServerConnectionCallback callback,
            JMXServiceURL address,
            Map env,
            SynchroMessageConnectionServer mcs,
            MBeanServer mbs) {
        this.facade = facade;
        this.callback = callback;
        this.env = env;
        this.connectingTimeout = DefaultConfig.getConnectingTimeout(env);
    }

    @Override
    public void start() throws IOException {
        final boolean tracing = logger.traceOn();
        synchronized (lock) {
            if (state == STARTED) {
                return;
            } else if (state == STOPPED) {
                throw new IOException("The server has been stopped.");
            }

            MBeanServer mbs = facade.getMBeanServer();
            if (mbs == null) {
                throw new IllegalStateException("This connector server is not attached to an MBean server");
            }

            if (env != null) {
                // PLAN-2.0.0 §7.6/§7.7: authorization is opt-in via a typed,
                // code-only JmxmpAccessControl under ENV_KEY. Absent ⇒ no
                // forwarder installed (authenticated-but-unrestricted; authn is
                // already mandatory). A non-JmxmpAccessControl value (e.g. a
                // String from -D/props) ⇒ fail CLOSED at server start, so the
                // code-only guarantee is enforced, not merely documented. The
                // legacy "jmx.remote.x.access.file" properties mechanism is
                // gone (MBeanServerFileAccessController hard-deleted).
                Object acValue = env.get(JmxmpAccessControl.ENV_KEY);
                if (acValue != null) {
                    if (!(acValue instanceof JmxmpAccessControl accessControl)) {
                        throw new SecurityException(JmxmpAccessControl.ENV_KEY
                                + " must be a code-supplied JmxmpAccessControl instance, but was "
                                + acValue.getClass().getName());
                    }
                    facade.setMBeanServerForwarder(new AccessControlledMBeanServer(accessControl));
                    mbs = facade.getMBeanServer();
                }
            }

            try {
                defaultClassLoader = EnvHelp.resolveServerClassLoader(env, mbs);
            } catch (InstanceNotFoundException infc) {
                IllegalArgumentException x = new IllegalArgumentException("ClassLoader not found: " + infc);
                throw (IllegalArgumentException) x.initCause(infc);
            }

            objectWrapping = (ObjectWrapping) env.get(OBJECT_WRAPPING);
            if (objectWrapping == null) {
                objectWrapping = new ObjectWrappingImpl();
            }

            MessageConnectionServer messageServer = (MessageConnectionServer) env.get(MESSAGE_CONNECTION_SERVER);
            if (messageServer == null) {
                // JMXMPConnectorServer passes the JMXServiceURL instead of
                // pre-building a SocketConnectionServer (keeps `common` server-free).
                Object u = env.get("com.druvu.jmxmp.x.server.url");
                if (u instanceof JMXServiceURL url) {
                    messageServer = new com.druvu.jmxmp.server.socket.SocketConnectionServer(url, env);
                }
            }
            if (messageServer == null) {
                sMsgServer = DefaultConfig.getSynchroMessageConnectionServer(env);
                if (sMsgServer == null) {
                    throw new IllegalArgumentException("No message connection server");
                }
            } else {
                sMsgServer = new SynchroMessageConnectionServerImpl(messageServer, env);
            }
            sMsgServer.start(env);

            state = STARTED;
            if (tracing) {
                logger.trace("start", "Connector Server Address = " + sMsgServer.getAddress());
            }

            receiver = new Receiver();
            receiver.start();
        }
    }

    @Override
    public void stop() throws IOException {
        final boolean debug = logger.debugOn();
        synchronized (lock) {
            if (state == STOPPED) {
                return;
            }
            state = STOPPED;

            if (sMsgServer != null) {
                sMsgServer.stop();
            }
            while (clientList.size() > 0) {
                try {
                    ServerIntermediary inter = (ServerIntermediary) clientList.remove(0);
                    inter.terminate();
                } catch (Exception e) {
                    logger.warning("stop", "Failed to stop client: " + e);
                    if (debug) {
                        logger.debug("stop", e);
                    }
                }
            }
            if (notifBuffer != null) {
                notifBuffer.dispose();
            }
            threads.terminate();
        }
        cancelConnecting.cancel();
    }

    @Override
    public boolean isActive() {
        synchronized (lock) {
            return state == STARTED;
        }
    }

    @Override
    public JMXServiceURL getAddress() {
        if (!isActive()) {
            return null;
        }
        return sMsgServer.getAddress();
    }

    @Override
    public String[] getConnectionIds() {
        // JMXConnectorServer (the facade super-type) is the authoritative
        // tracker, fed via the callback; engine keeps no separate registry.
        return new String[0];
    }

    @Override
    public void setMBeanServerForwarder(MBeanServerForwarder mbsf) {
        facade.setMBeanServerForwarder(mbsf);
    }

    @Override
    public void close() throws IOException {
        stop();
    }

    /** Lazily created when the first client connects (called by ServerIntermediary). */
    synchronized NotificationBuffer getNotifBuffer() {
        if (notifBuffer == null) {
            notifBuffer = ArrayNotificationBuffer.getNotificationBuffer(facade.getMBeanServer(), env);
        }
        return notifBuffer;
    }

    /** Called by {@link ServerIntermediary} on client termination. */
    void clientClosing(ServerIntermediary inter, String connectionId, String msg, Object userData) {
        synchronized (lock) {
            clientList.remove(inter);
        }
        callback.connectionClosed(connectionId, msg, userData);
    }

    /** Called by {@link ServerIntermediary} on a failed connection. */
    void failedConnectionNotif(String connectionId, String message, Object userData) {
        callback.connectionFailed(connectionId, message, userData);
    }

    // ----------------------------------------------
    // private classes
    // ----------------------------------------------

    private class Receiver extends Thread {

        public void run() {
            while (isActive()) {
                final boolean tracing = logger.traceOn();
                final boolean debug = logger.debugOn();
                ServerSynchroMessageConnection connection;

                try {
                    connection = sMsgServer.accept();
                } catch (IOException ioe) {
                    if (isActive()) {
                        logger.error("Receiver.run", "Unexpected IOException: " + ioe);
                        if (debug) {
                            logger.debug("Receiver.run", ioe);
                        }
                        try {
                            GenericConnectorServerEngineImpl.this.stop();
                        } catch (IOException ie) {
                            logger.warning("Receiver.run", "Failed to stop server: " + ie);
                        }
                    } else if (tracing) {
                        logger.trace("Receiver.run", "interrupted: " + ioe);
                    }
                    break;
                }

                if (!isActive()) {
                    return;
                }

                ClientCreation cc = new ClientCreation(connection);
                if (connectingTimeout <= 0) {
                    threads.handoff(cc);
                } else {
                    ConnectingStopper stopper = new ConnectingStopper(cc);
                    cc.setStopper(stopper);
                    threads.handoff(cc);
                    cancelConnecting.schedule(stopper, connectingTimeout);
                }
            }
        }
    }

    private class ClientCreation implements Runnable {
        ServerSynchroMessageConnection connection;
        private boolean done = false;
        private ConnectingStopper stopper;

        ClientCreation(ServerSynchroMessageConnection connection) {
            this.connection = connection;
        }

        void setStopper(ConnectingStopper stopper) {
            this.stopper = stopper;
        }

        public void run() {
            final boolean tracing = logger.traceOn();
            Subject subject = null;
            boolean failed = false;

            try {
                connection.connect(env);
                subject = connection.getSubject();
            } catch (Throwable e) {
                failed = true;
                logger.warning("ClientCreation.run", "Failed to open connection: " + e, e);
                try {
                    connection.close();
                } catch (Exception ee) {
                    if (logger.debugOn()) {
                        logger.debug("ClientCreation.run", "Failed to cleanup: " + ee);
                    }
                }
            }

            synchronized (this) {
                if (done) {
                    failed = true;
                } else {
                    done = true;
                    if (stopper != null) {
                        stopper.cancel();
                    }
                }
            }
            if (failed) {
                return;
            }

            final ServerIntermediary inter = new ServerIntermediary(
                    facade.getMBeanServer(),
                    GenericConnectorServerEngineImpl.this,
                    connection,
                    objectWrapping,
                    subject,
                    defaultClassLoader,
                    env);

            synchronized (lock) {
                if (state != STARTED) {
                    try {
                        inter.terminate();
                    } catch (Exception e) {
                        if (logger.debugOn()) {
                            logger.debug("ClientCreation.run", "Failed to cleanup: " + e);
                        }
                    }
                    return;
                }
                clientList.add(inter);
            }

            final String cid = connection.getConnectionId();
            callback.connectionOpened(cid, "New client connection " + cid + " has been established", null);

            inter.start();
        }
    }

    private class ConnectingStopper extends TimerTask {
        private final ClientCreation cc;

        ConnectingStopper(ClientCreation cc) {
            this.cc = cc;
        }

        public void run() {
            synchronized (cc) {
                if (cc.done) {
                    return;
                }
                cc.done = true;
            }
            try {
                cc.connection.close();
            } catch (Exception e) {
                if (logger.debugOn()) {
                    logger.debug("ConnectingStopper.run", e);
                }
            }
        }
    }
}
