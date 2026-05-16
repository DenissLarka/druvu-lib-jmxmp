/*
 * GenericConnectorEngineProviderImpl.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.client.generic;

import com.druvu.jmxmp.spi.EngineCallback;
import com.druvu.jmxmp.spi.GenericConnectorEngine;
import com.druvu.jmxmp.spi.GenericConnectorEngineProvider;
import java.util.Map;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.generic.MessageConnection;

/** ServiceLoader provider for the client-side connector engine. */
public final class GenericConnectorEngineProviderImpl implements GenericConnectorEngineProvider {

    @Override
    public GenericConnectorEngine newEngine(
            JMXConnector facade,
            EngineCallback callback,
            JMXServiceURL address,
            Map<String, ?> env,
            MessageConnection messageConnection) {
        return new GenericConnectorEngineImpl(facade, callback, address, env, messageConnection);
    }
}
