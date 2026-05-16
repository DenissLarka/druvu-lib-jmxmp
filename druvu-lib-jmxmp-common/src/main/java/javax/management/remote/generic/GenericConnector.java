/*
 * @(#)file      GenericConnector.java
 * @(#)author    Sun Microsystems, Inc.
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2007 Sun Microsystems, Inc. All Rights Reserved.
 *
 * The contents of this file are subject to the terms of either the GNU General
 * Public License Version 2 only ("GPL") or the Common Development and
 * Distribution License("CDDL")(collectively, the "License"). You may not use
 * this file except in compliance with the License. See the LICENSE file at the
 * repo root. Sun designates this file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License.
 *
 * Portions Copyrighted 2026 — com.druvu fork (2.0): rewritten as a thin
 * facade over the ServiceLoader-discovered client engine
 * (com.druvu.jmxmp.spi.GenericConnectorEngine). The public/protected API
 * surface (JMXConnector + protected sendNotification + the OBJECT_WRAPPING /
 * MESSAGE_CONNECTION constants) is preserved bit-for-bit; all connection
 * state and behaviour moved to com.druvu.jmxmp.client.generic.
 */

package javax.management.remote.generic;

import com.druvu.jmxmp.shared.CheckProfiles;
import com.druvu.jmxmp.spi.EngineCallback;
import com.druvu.jmxmp.spi.GenericConnectorEngine;
import com.druvu.jmxmp.spi.GenericConnectorEngineProvider;
import com.druvu.jmxmp.util.ThreadService;
import java.io.IOException;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;
import javax.management.ListenerNotFoundException;
import javax.management.MBeanServerConnection;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.management.remote.JMXConnector;
import javax.security.auth.Subject;

/**
 * A connector that connects to a remote JMX API server through a {@link MessageConnection}. Since 2.0 this class is a
 * thin facade: the implementation is supplied at runtime by a {@link GenericConnectorEngineProvider} located via
 * {@link ServiceLoader} (the {@code com.druvu.jmxmp.client} module). The mandatory {@code TLS SASL/PLAIN} policy is
 * enforced here, before any engine is created, so it holds even for subclasses.
 */
public class GenericConnector implements JMXConnector, Serializable {

    private static final long serialVersionUID = 2_000_000L;

    /**
     * Name of the attribute that specifies the object wrapping for parameters whose deserialization requires special
     * treatment.
     */
    public static final String OBJECT_WRAPPING = "jmx.remote.object.wrapping";

    /** Name of the attribute that specifies how this connector sends messages to its connector server. */
    public static final String MESSAGE_CONNECTION = "jmx.remote.message.connection";

    private transient GenericConnectorEngine engine;
    private transient NotificationBroadcasterSupport connectionBroadcaster;
    private transient ThreadService notifThread;
    private transient Map env;

    /** Default no-arg constructor (needed for subclass serialization). */
    public GenericConnector() {
        this(null);
    }

    /**
     * Constructor specifying connection attributes.
     *
     * @param env the attributes of the connection.
     */
    public GenericConnector(Map env) {
        if (env == null) {
            // Serialization-only path; policy still enforced at connect().
            this.env = Collections.EMPTY_MAP;
        } else {
            this.env = Collections.unmodifiableMap(env);
            // Mandatory policy (2.0): explicit env must specify exactly
            // jmx.remote.profiles="TLS SASL/PLAIN".
            CheckProfiles.enforceSpec((String) env.get("jmx.remote.profiles"), env);
        }
        connectionBroadcaster = new NotificationBroadcasterSupport();
    }

    public void connect() throws IOException {
        connect(null);
    }

    public void connect(Map env) throws IOException {
        synchronized (this) {
            if (engine != null && engine.isConnected()) {
                return;
            }
            Map merged = new HashMap(this.env == null ? Collections.EMPTY_MAP : this.env);
            if (env != null) {
                merged.putAll(env);
            }
            // Mandatory policy (2.0), unconditional client gate. Holds even
            // for subclasses that bypass the constructor or override connect().
            CheckProfiles.enforceSpec((String) merged.get("jmx.remote.profiles"), merged);

            if (connectionBroadcaster == null) {
                connectionBroadcaster = new NotificationBroadcasterSupport();
            }
            if (notifThread == null) {
                notifThread = new ThreadService(0, 1);
            }
            if (engine == null) {
                GenericConnectorEngineProvider provider = ServiceLoader.load(GenericConnectorEngineProvider.class)
                        .findFirst()
                        .orElseThrow(() ->
                                new IllegalStateException("No GenericConnectorEngineProvider implementation found; "
                                        + "add com.druvu.jmxmp.client to the module path / classpath"));
                engine = provider.newEngine(
                        this,
                        (EngineCallback) this::sendNotification,
                        null,
                        merged,
                        (javax.management.remote.generic.MessageConnection) merged.get(MESSAGE_CONNECTION));
            }
            engine.connect(merged);
            this.env = merged;
        }
    }

    public String getConnectionId() throws IOException {
        if (engine == null) {
            throw new IOException("The client has not been connected.");
        }
        return engine.getConnectionId();
    }

    public MBeanServerConnection getMBeanServerConnection() throws IOException {
        return getMBeanServerConnection(null);
    }

    public MBeanServerConnection getMBeanServerConnection(Subject delegationSubject) throws IOException {
        if (engine == null) {
            throw new IOException("The client has not been connected.");
        }
        return engine.getMBeanServerConnection(delegationSubject);
    }

    public void close() throws IOException {
        if (engine != null) {
            engine.close();
        }
    }

    public void addConnectionNotificationListener(
            NotificationListener listener, NotificationFilter filter, Object handback) {
        if (listener == null) {
            throw new NullPointerException("listener");
        }
        connectionBroadcaster.addNotificationListener(listener, filter, handback);
    }

    public void removeConnectionNotificationListener(NotificationListener listener) throws ListenerNotFoundException {
        if (listener == null) {
            throw new NullPointerException("listener");
        }
        connectionBroadcaster.removeNotificationListener(listener);
    }

    public void removeConnectionNotificationListener(
            NotificationListener listener, NotificationFilter filter, Object handback)
            throws ListenerNotFoundException {
        if (listener == null) {
            throw new NullPointerException("listener");
        }
        connectionBroadcaster.removeNotificationListener(listener, filter, handback);
    }

    /**
     * Send a notification to the connection listeners. Dispatched asynchronously, exactly as the original
     * implementation.
     *
     * @param n the notification to send (usually a {@code JMXConnectionNotification}).
     */
    protected void sendNotification(final Notification n) {
        final NotificationBroadcasterSupport b = connectionBroadcaster;
        Runnable job = () -> {
            try {
                b.sendNotification(n);
            } catch (Exception e) {
                // OK — never
            }
        };
        if (notifThread != null) {
            notifThread.handoff(job);
        } else {
            job.run();
        }
    }
}
