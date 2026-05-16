/*
 * GenericConnectorServerEngineProvider.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.spi;

import com.druvu.jmxmp.shared.SynchroMessageConnectionServer;
import java.util.Map;
import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXServiceURL;

/**
 * {@link java.util.ServiceLoader} SPI implemented by the {@code com.druvu.jmxmp.server} module; consumed by the
 * {@code GenericConnectorServer} facade in {@code common}.
 *
 * <p>The {@code facade} parameter is typed as {@link JMXConnectorServer} (the JDK super-type the facade extends) rather
 * than the concrete {@code javax.management.remote.generic.GenericConnectorServer}, for the same decoupling reason as
 * {@link GenericConnectorEngineProvider}. The facade passes {@code this}. Internal SPI, evolvable.
 */
public interface GenericConnectorServerEngineProvider {

    GenericConnectorServerEngine newEngine(
            JMXConnectorServer facade,
            ServerConnectionCallback callback,
            JMXServiceURL address,
            Map<String, ?> env,
            SynchroMessageConnectionServer mcs,
            MBeanServer mbs);
}
