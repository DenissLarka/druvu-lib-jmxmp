/*
 * GenericConnectorServerEngineProviderImpl.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.server.generic;

import com.druvu.jmxmp.shared.SynchroMessageConnectionServer;
import com.druvu.jmxmp.spi.GenericConnectorServerEngine;
import com.druvu.jmxmp.spi.GenericConnectorServerEngineProvider;
import com.druvu.jmxmp.spi.ServerConnectionCallback;
import java.util.Map;
import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXServiceURL;

/** ServiceLoader provider for the server-side connector engine. */
public final class GenericConnectorServerEngineProviderImpl implements GenericConnectorServerEngineProvider {

    @Override
    public GenericConnectorServerEngine newEngine(
            JMXConnectorServer facade,
            ServerConnectionCallback callback,
            JMXServiceURL address,
            Map<String, ?> env,
            SynchroMessageConnectionServer mcs,
            MBeanServer mbs) {
        return new GenericConnectorServerEngineImpl(facade, callback, address, env, mcs, mbs);
    }
}
