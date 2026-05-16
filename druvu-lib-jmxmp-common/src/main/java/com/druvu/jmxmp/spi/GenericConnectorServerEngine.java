/*
 * GenericConnectorServerEngine.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.spi;

import java.io.Closeable;
import java.io.IOException;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.MBeanServerForwarder;

/**
 * Server-side connector engine: the implementation half of the
 * {@code javax.management.remote.generic.GenericConnectorServer} facade. Lives in the {@code com.druvu.jmxmp.server}
 * module, discovered via {@link java.util.ServiceLoader} through {@link GenericConnectorServerEngineProvider}.
 *
 * <p>Internal SPI — not part of the public OpenDMK API.
 */
public interface GenericConnectorServerEngine extends Closeable {

    void start() throws IOException;

    void stop() throws IOException;

    boolean isActive();

    JMXServiceURL getAddress();

    String[] getConnectionIds();

    void setMBeanServerForwarder(MBeanServerForwarder mbsf);

    @Override
    void close() throws IOException;
}
