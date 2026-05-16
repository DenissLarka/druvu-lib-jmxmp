/*
 * GenericConnectorEngineImpl.java
 *
 * Client-side engine extracted from the OpenDMK GenericConnector in the
 * com.druvu fork (2.0). Behaviour is preserved from the original Sun code
 * (Copyright (c) 2007 Sun Microsystems, Inc.); the facade/engine split,
 * notification-via-callback wiring and package moves are fork changes.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.client.generic;

import com.druvu.jmxmp.shared.ClientCommunicatorAdmin;
import com.druvu.jmxmp.shared.ClientSynchroMessageConnection;
import com.druvu.jmxmp.shared.DefaultConfig;
import com.druvu.jmxmp.shared.ObjectWrappingImpl;
import com.druvu.jmxmp.shared.SynchroCallback;
import com.druvu.jmxmp.spi.EngineCallback;
import com.druvu.jmxmp.spi.GenericConnectorEngine;
import com.druvu.jmxmp.util.ClassLogger;
import java.io.IOException;
import java.util.Map;
import java.util.WeakHashMap;
import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.IntrospectionException;
import javax.management.InvalidAttributeValueException;
import javax.management.ListenerNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanInfo;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServerConnection;
import javax.management.NotCompliantMBeanException;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.QueryExp;
import javax.management.ReflectionException;
import javax.management.remote.JMXConnectionNotification;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.generic.MessageConnection;
import javax.management.remote.generic.ObjectWrapping;
import javax.management.remote.message.CloseMessage;
import javax.management.remote.message.Message;
import javax.security.auth.Subject;

/**
 * Implementation half of the {@code javax.management.remote.generic .GenericConnector} facade. Holds all connection
 * state and the {@link ClientIntermediary}; the facade delegates the {@code JMXConnector} lifecycle here and supplies
 * an {@link EngineCallback} so connection notifications still originate from the facade's broadcaster.
 */
public final class GenericConnectorEngineImpl implements GenericConnectorEngine {

    // env keys — inlined to avoid an engine -> facade compile edge.
    private static final String MESSAGE_CONNECTION = "jmx.remote.message.connection";
    private static final String OBJECT_WRAPPING = "jmx.remote.object.wrapping";

    private static final int CREATED = 1;
    private static final int CONNECTED = 2;
    private static final int CLOSED = 3;

    private final JMXConnector facade;
    private final EngineCallback callback;

    private ClientSynchroMessageConnection connection;
    private ObjectWrapping objectWrapping;
    private Map env;
    private ClientIntermediary clientMBeanServer;
    private final WeakHashMap rmbscMap = new WeakHashMap();
    private String connectionId;
    private RequestHandler requestHandler;
    private final int[] lock = new int[0];
    private int state = CREATED;
    private long seq = 0;

    private static final ClassLogger logger =
            new ClassLogger("com.druvu.jmxmp.client.generic", "GenericConnectorEngineImpl");

    public GenericConnectorEngineImpl(
            JMXConnector facade, EngineCallback callback, JMXServiceURL address, Map env, MessageConnection mc) {
        this.facade = facade;
        this.callback = callback;
    }

    @Override
    public void connect(Map<String, ?> connectEnv) throws IOException {
        final boolean tracing = logger.traceOn();

        synchronized (lock) {
            switch (state) {
                case CREATED:
                    break;
                case CONNECTED:
                    return;
                case CLOSED:
                    throw new IOException("Connector already closed.");
                default:
                    throw new IOException("Invalid state (" + state + ")");
            }

            @SuppressWarnings("unchecked")
            Map env = (Map) connectEnv;

            MessageConnection conn = (MessageConnection) env.get(MESSAGE_CONNECTION);
            if (conn == null) {
                // JMXMPConnector now passes the JMXServiceURL instead of
                // pre-building a SocketConnection (keeps `common` client-free).
                Object u = env.get("com.druvu.jmxmp.x.url");
                if (u instanceof javax.management.remote.JMXServiceURL url) {
                    conn = new com.druvu.jmxmp.shared.SocketConnection(url.getHost(), url.getPort());
                }
            }
            if (conn == null) {
                connection = DefaultConfig.getClientSynchroMessageConnection(env);
                if (connection == null) {
                    throw new IllegalArgumentException("No MessageConnection");
                }
            } else {
                requestHandler = new RequestHandler();
                connection = new ClientSynchroMessageConnectionImpl(conn, requestHandler, env);
            }
            connection.connect(env);
            connectionId = connection.getConnectionId();

            objectWrapping = (ObjectWrapping) env.get(OBJECT_WRAPPING);
            if (objectWrapping == null) {
                objectWrapping = new ObjectWrappingImpl();
            }

            clientMBeanServer = new ClientIntermediary(connection, objectWrapping, this, env);

            this.env = env;
            state = CONNECTED;
            if (tracing) {
                logger.trace("connect", connectionId + " Connected.");
            }
        }

        callback.sendNotification(new JMXConnectionNotification(
                JMXConnectionNotification.OPENED, facade, connectionId, seq++, null, null));
    }

    @Override
    public MBeanServerConnection getMBeanServerConnection(Subject delegationSubject) throws IOException {
        checkState();
        if (rmbscMap.containsKey(delegationSubject)) {
            return (MBeanServerConnection) rmbscMap.get(delegationSubject);
        }
        RemoteMBeanServerConnection rmbsc = new RemoteMBeanServerConnection(clientMBeanServer, delegationSubject);
        rmbscMap.put(delegationSubject, rmbsc);
        return rmbsc;
    }

    @Override
    public String getConnectionId() throws IOException {
        checkState();
        return connection.getConnectionId();
    }

    @Override
    public boolean isConnected() {
        synchronized (lock) {
            return state == CONNECTED;
        }
    }

    @Override
    public void close() throws IOException {
        close(false, "The connection is closed by a user.");
    }

    void close(boolean local, String msg) throws IOException {
        final boolean tracing = logger.traceOn();
        final boolean debug = logger.debugOn();
        Exception closeException;
        boolean createdState;

        synchronized (lock) {
            if (state == CLOSED) {
                return;
            }
            createdState = (state == CREATED);
            state = CLOSED;
            closeException = null;

            if (!createdState) {
                if (!local) {
                    try {
                        synchronized (connection) {
                            connection.sendOneWay(new CloseMessage(msg));
                            Thread.sleep(100);
                        }
                    } catch (InterruptedException ire) {
                        // OK
                    } catch (Exception e1) {
                        closeException = e1;
                        if (debug) {
                            logger.debug("close", e1);
                        }
                    }
                }
                try {
                    connection.close();
                } catch (Exception e1) {
                    closeException = e1;
                    if (debug) {
                        logger.debug("close", e1);
                    }
                }
            }

            if (clientMBeanServer != null) {
                clientMBeanServer.terminate();
            }
            rmbscMap.clear();
        }

        if (!createdState) {
            callback.sendNotification(new JMXConnectionNotification(
                    JMXConnectionNotification.CLOSED,
                    facade,
                    connectionId,
                    seq++,
                    "The client has been closed.",
                    null));
        }

        if (closeException != null) {
            if (closeException instanceof RuntimeException) {
                throw (RuntimeException) closeException;
            }
            if (closeException instanceof IOException) {
                throw (IOException) closeException;
            }
            final IOException x = new IOException("Failed to close: " + closeException);
            throw (IOException) x.initCause(closeException);
        }
        if (tracing) {
            logger.trace("close", "closed.");
        }
    }

    /** Called by {@link ClientIntermediary} to re-establish the transport after a server-side timeout close. */
    ClientSynchroMessageConnection reconnect() throws IOException {
        synchronized (lock) {
            if (state != CONNECTED) {
                throw new IOException("The connector is not at the connection state.");
            }
        }

        callback.sendNotification(new JMXConnectionNotification(
                JMXConnectionNotification.FAILED,
                facade,
                connectionId,
                seq++,
                "The client has got connection exception.",
                null));

        connection.connect(env);
        connectionId = connection.getConnectionId();

        callback.sendNotification(new JMXConnectionNotification(
                JMXConnectionNotification.OPENED,
                facade,
                connectionId,
                seq++,
                "The client has succesfully reconnected to the server.",
                null));

        return connection;
    }

    /** Called by {@link ClientIntermediary} to forward a notification. */
    void sendNotification(javax.management.Notification n) {
        callback.sendNotification(n);
    }

    private void checkState() throws IOException {
        synchronized (lock) {
            if (state == CREATED) {
                throw new IOException("The client has not been connected.");
            } else if (state == CLOSED) {
                throw new IOException("The client has been closed.");
            }
        }
    }

    // ----------------------------------------------
    // private classes
    // ----------------------------------------------

    private static class RemoteMBeanServerConnection implements MBeanServerConnection {

        private final ClientIntermediary ci;
        private final Subject ds;

        RemoteMBeanServerConnection(ClientIntermediary ci) {
            this(ci, null);
        }

        RemoteMBeanServerConnection(ClientIntermediary ci, Subject ds) {
            this.ci = ci;
            this.ds = ds;
        }

        public ObjectInstance createMBean(String className, ObjectName name)
                throws ReflectionException, InstanceAlreadyExistsException, MBeanException, NotCompliantMBeanException,
                        IOException {
            return ci.createMBean(className, name, ds);
        }

        public ObjectInstance createMBean(String className, ObjectName name, ObjectName loaderName)
                throws ReflectionException, InstanceAlreadyExistsException, MBeanException, NotCompliantMBeanException,
                        InstanceNotFoundException, IOException {
            return ci.createMBean(className, name, loaderName, ds);
        }

        public ObjectInstance createMBean(String className, ObjectName name, Object params[], String signature[])
                throws ReflectionException, InstanceAlreadyExistsException, MBeanException, NotCompliantMBeanException,
                        IOException {
            return ci.createMBean(className, name, params, signature, ds);
        }

        public ObjectInstance createMBean(
                String className, ObjectName name, ObjectName loaderName, Object params[], String signature[])
                throws ReflectionException, InstanceAlreadyExistsException, MBeanException, NotCompliantMBeanException,
                        InstanceNotFoundException, IOException {
            return ci.createMBean(className, name, loaderName, params, signature, ds);
        }

        public void unregisterMBean(ObjectName name)
                throws InstanceNotFoundException, MBeanRegistrationException, IOException {
            ci.unregisterMBean(name, ds);
        }

        public ObjectInstance getObjectInstance(ObjectName name) throws InstanceNotFoundException, IOException {
            return ci.getObjectInstance(name, ds);
        }

        public java.util.Set queryMBeans(ObjectName name, QueryExp query) throws IOException {
            return ci.queryMBeans(name, query, ds);
        }

        public java.util.Set queryNames(ObjectName name, QueryExp query) throws IOException {
            return ci.queryNames(name, query, ds);
        }

        public boolean isRegistered(ObjectName name) throws IOException {
            return ci.isRegistered(name, ds);
        }

        public Integer getMBeanCount() throws IOException {
            return ci.getMBeanCount(ds);
        }

        public Object getAttribute(ObjectName name, String attribute)
                throws MBeanException, AttributeNotFoundException, InstanceNotFoundException, ReflectionException,
                        IOException {
            return ci.getAttribute(name, attribute, ds);
        }

        public AttributeList getAttributes(ObjectName name, String[] attributes)
                throws InstanceNotFoundException, ReflectionException, IOException {
            return ci.getAttributes(name, attributes, ds);
        }

        public void setAttribute(ObjectName name, Attribute attribute)
                throws InstanceNotFoundException, AttributeNotFoundException, InvalidAttributeValueException,
                        MBeanException, ReflectionException, IOException {
            ci.setAttribute(name, attribute, ds);
        }

        public AttributeList setAttributes(ObjectName name, AttributeList attributes)
                throws InstanceNotFoundException, ReflectionException, IOException {
            return ci.setAttributes(name, attributes, ds);
        }

        public Object invoke(ObjectName name, String operationName, Object params[], String signature[])
                throws InstanceNotFoundException, MBeanException, ReflectionException, IOException {
            return ci.invoke(name, operationName, params, signature, ds);
        }

        public String getDefaultDomain() throws IOException {
            return ci.getDefaultDomain(ds);
        }

        public String[] getDomains() throws IOException {
            return ci.getDomains(ds);
        }

        public void addNotificationListener(
                ObjectName name, NotificationListener listener, NotificationFilter filter, Object handback)
                throws InstanceNotFoundException, IOException {
            ci.addNotificationListener(name, listener, filter, handback, ds);
        }

        public void addNotificationListener(
                ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
                throws InstanceNotFoundException, IOException {
            ci.addNotificationListener(name, listener, filter, handback, ds);
        }

        public void removeNotificationListener(ObjectName name, ObjectName listener)
                throws InstanceNotFoundException, ListenerNotFoundException, IOException {
            ci.removeNotificationListener(name, listener, ds);
        }

        public void removeNotificationListener(
                ObjectName name, ObjectName listener, NotificationFilter filter, Object handback)
                throws InstanceNotFoundException, ListenerNotFoundException, IOException {
            ci.removeNotificationListener(name, listener, filter, handback, ds);
        }

        public void removeNotificationListener(ObjectName name, NotificationListener listener)
                throws InstanceNotFoundException, ListenerNotFoundException, IOException {
            ci.removeNotificationListener(name, listener, ds);
        }

        public void removeNotificationListener(
                ObjectName name, NotificationListener listener, NotificationFilter filter, Object handback)
                throws InstanceNotFoundException, ListenerNotFoundException, IOException {
            ci.removeNotificationListener(name, listener, filter, handback, ds);
        }

        public MBeanInfo getMBeanInfo(ObjectName name)
                throws InstanceNotFoundException, IntrospectionException, ReflectionException, IOException {
            return ci.getMBeanInfo(name, ds);
        }

        public boolean isInstanceOf(ObjectName name, String className) throws InstanceNotFoundException, IOException {
            return ci.isInstanceOf(name, className, ds);
        }
    }

    private class RequestHandler implements SynchroCallback {

        public Message execute(Message msg) {
            if (msg instanceof CloseMessage) {
                if (logger.traceOn()) {
                    logger.trace("RequestHandler-execute", "got Message REMOTE_TERMINATION");
                }
                try {
                    ClientCommunicatorAdmin admin = clientMBeanServer.getCommunicatorAdmin();
                    admin.gotIOException(new IOException(""));
                    return null;
                } catch (IOException ioe) {
                    // the server has been closed.
                }
                try {
                    GenericConnectorEngineImpl.this.close(true, null);
                } catch (IOException ie) {
                    // OK never
                }
            } else {
                final String errstr = ((msg == null) ? "null" : msg.getClass().getName()) + ": Bad message type.";
                logger.warning("RequestHandler-execute", errstr);
                try {
                    logger.warning("RequestHandler-execute", "Closing connector");
                    GenericConnectorEngineImpl.this.close(false, null);
                } catch (IOException ie) {
                    logger.info("RequestHandler-execute", ie);
                }
            }
            return null;
        }

        public void connectionException(Exception e) {
            synchronized (lock) {
                if (state != CONNECTED) {
                    return;
                }
            }
            logger.warning("RequestHandler-connectionException", e);
            if (e instanceof IOException) {
                try {
                    ClientCommunicatorAdmin admin = clientMBeanServer.getCommunicatorAdmin();
                    admin.gotIOException((IOException) e);
                    return;
                } catch (IOException ioe) {
                    // closing at the following steps
                }
            }
            synchronized (lock) {
                if (state == CONNECTED) {
                    logger.warning("RequestHandler-connectionException", "Got connection exception: " + e.toString());
                    try {
                        GenericConnectorEngineImpl.this.close(true, null);
                    } catch (IOException ie) {
                        logger.info("RequestHandler-execute", ie);
                    }
                }
            }
        }
    }

    private static class ResponseMsgWrapper {
        public boolean got = false;
        public Message msg = null;

        public ResponseMsgWrapper() {}

        public void setMsg(Message msg) {
            got = true;
            this.msg = msg;
        }
    }
}
