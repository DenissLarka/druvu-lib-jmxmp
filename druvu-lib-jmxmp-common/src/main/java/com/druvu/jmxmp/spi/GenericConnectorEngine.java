/*
 * GenericConnectorEngine.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.spi;

import java.io.Closeable;
import java.io.IOException;
import java.util.Map;
import javax.management.MBeanServerConnection;
import javax.security.auth.Subject;

/**
 * Client-side connector engine: the implementation half of the {@code javax.management.remote.generic.GenericConnector}
 * facade. Lives in the {@code com.druvu.jmxmp.client} module and is discovered by the facade via
 * {@link java.util.ServiceLoader} through {@link GenericConnectorEngineProvider}.
 *
 * <p>Internal SPI — not part of the public OpenDMK API.
 */
public interface GenericConnectorEngine extends Closeable {

    /** Establish the connection using the (already policy-checked) env. */
    void connect(Map<String, ?> env) throws IOException;

    /** The live MBean server connection, optionally for a delegation subject. */
    MBeanServerConnection getMBeanServerConnection(Subject delegationSubject) throws IOException;

    String getConnectionId() throws IOException;

    boolean isConnected();

    @Override
    void close() throws IOException;
}
