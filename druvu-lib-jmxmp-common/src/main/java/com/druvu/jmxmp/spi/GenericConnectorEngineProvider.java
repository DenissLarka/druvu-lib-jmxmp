/*
 * GenericConnectorEngineProvider.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.spi;

import java.util.Map;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.generic.MessageConnection;

/**
 * {@link java.util.ServiceLoader} SPI implemented by the {@code com.druvu.jmxmp.client} module; consumed by the
 * {@code GenericConnector} facade in {@code common}.
 *
 * <p>The {@code facade} parameter is typed as {@link JMXConnector} (the JDK super-type the facade implements) rather
 * than the concrete {@code javax.management.remote.generic.GenericConnector}: an SPI seam must not compile-couple
 * {@code common} to a concrete facade. The facade passes {@code this}, which is-a {@code JMXConnector}. Internal SPI,
 * evolvable — not public OpenDMK API.
 */
public interface GenericConnectorEngineProvider {

    GenericConnectorEngine newEngine(
            JMXConnector facade,
            EngineCallback callback,
            JMXServiceURL address,
            Map<String, ?> env,
            MessageConnection messageConnection);
}
