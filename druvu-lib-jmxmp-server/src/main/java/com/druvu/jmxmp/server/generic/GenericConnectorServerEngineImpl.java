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

import com.druvu.jmxmp.access.AccessControlledMBeanServer;
import com.druvu.jmxmp.access.JmxAccessControl;
import com.druvu.jmxmp.internal.DefaultConfig;
import com.druvu.jmxmp.internal.ObjectWrappingImpl;
import com.druvu.jmxmp.internal.ServerSynchroMessageConnection;
import com.druvu.jmxmp.internal.SynchroMessageConnectionServer;
import com.druvu.jmxmp.server.internal.ArrayNotificationBuffer;
import com.druvu.jmxmp.server.internal.NotificationBuffer;
import com.druvu.jmxmp.spi.GenericConnectorServerEngine;
import com.druvu.jmxmp.spi.ServerConnectionCallback;
import com.druvu.jmxmp.util.ConnectorThreads;
import com.druvu.jmxmp.util.EnvHelp;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.util.ArrayList;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.ExecutorService;
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
    private final ExecutorService threads = ConnectorThreads.pool("server-accept", 10);
    private final ArrayList clientList = new ArrayList();
    private int state = CREATED;
    private final int[] lock = new int[0];
    private NotificationBuffer notifBuffer;
    private final Timer cancelConnecting = new Timer(true);

    private static final System.Logger LOG = System.getLogger(GenericConnectorServerEngineImpl.class.getName());

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
        final boolean tracing = LOG.isLoggable(Level.TRACE);
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

            // Authorization is opt-in via a typed, code-only JmxAccessControl
            // under ENV_KEY: absent ⇒ allowAll (authenticated-but-unrestricted;
            // authn is already mandatory); an instance ⇒ enforced per operation;
            // a non-JmxAccessControl value (e.g. a String from -D/props) ⇒ fail
            // CLOSED at server start, so the code-only guarantee is enforced, not
            // merely documented. The legacy "jmx.remote.x.access.file" mechanism
            // is gone (MBeanServerFileAccessController hard-deleted).
            //
            // The AccessControlledMBeanServer forwarder is installed UNCONDITIONALLY
            // (even for allowAll): it is the choke point that permanently denies
            // remote MBean lifecycle/deserialization regardless of the configured
            // control. That denial must be an invariant of every secured server,
            // not a function of whether a policy happens to be supplied.
            Object acValue = (env != null) ? env.get(JmxAccessControl.ENV_KEY) : null;
            JmxAccessControl accessControl;
            if (acValue == null) {
                accessControl = JmxAccessControl.allowAll();
            } else if (acValue instanceof JmxAccessControl supplied) {
                accessControl = supplied;
            } else {
                throw new SecurityException(JmxAccessControl.ENV_KEY
                        + " must be a code-supplied JmxAccessControl instance, but was "
                        + acValue.getClass().getName());
            }
            facade.setMBeanServerForwarder(new AccessControlledMBeanServer(accessControl));
            mbs = facade.getMBeanServer();

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
                LOG.log(Level.TRACE, "Connector Server Address = " + sMsgServer.getAddress());
            }

            receiver = new Receiver();
            receiver.start();
        }
    }

    @Override
    public void stop() throws IOException {
        final boolean debug = LOG.isLoggable(Level.TRACE);
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
                    LOG.log(Level.WARNING, "Failed to stop client: " + e);
                    if (debug) {
                        LOG.log(Level.TRACE, e.toString(), e);
                    }
                }
            }
            if (notifBuffer != null) {
                notifBuffer.dispose();
            }
            ConnectorThreads.stop(threads);
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
                final boolean tracing = LOG.isLoggable(Level.TRACE);
                final boolean debug = LOG.isLoggable(Level.TRACE);
                ServerSynchroMessageConnection connection;

                try {
                    connection = sMsgServer.accept();
                } catch (IOException ioe) {
                    if (isActive()) {
                        LOG.log(Level.ERROR, "Unexpected IOException: " + ioe);
                        if (debug) {
                            LOG.log(Level.TRACE, ioe.toString(), ioe);
                        }
                        try {
                            GenericConnectorServerEngineImpl.this.stop();
                        } catch (IOException ie) {
                            LOG.log(Level.WARNING, "Failed to stop server: " + ie);
                        }
                    } else if (tracing) {
                        LOG.log(Level.TRACE, "interrupted: " + ioe);
                    }
                    break;
                }

                if (!isActive()) {
                    return;
                }

                ClientCreation cc = new ClientCreation(connection);
                if (connectingTimeout <= 0) {
                    threads.execute(cc);
                } else {
                    ConnectingStopper stopper = new ConnectingStopper(cc);
                    cc.setStopper(stopper);
                    threads.execute(cc);
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
            final boolean tracing = LOG.isLoggable(Level.TRACE);
            Subject subject = null;
            boolean failed = false;

            try {
                connection.connect(env);
                subject = connection.getSubject();
            } catch (Throwable e) {
                failed = true;
                LOG.log(Level.WARNING, "Failed to open connection: " + e, e);
                try {
                    connection.close();
                } catch (Exception ee) {
                    LOG.log(Level.TRACE, () -> "Failed to cleanup: " + ee);
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
                        LOG.log(Level.TRACE, () -> "Failed to cleanup: " + e);
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
                LOG.log(Level.TRACE, () -> e.toString(), e);
            }
        }
    }
}
