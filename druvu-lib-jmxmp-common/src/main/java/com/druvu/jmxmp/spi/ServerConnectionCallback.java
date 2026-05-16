/*
 * ServerConnectionCallback.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.spi;

/**
 * Server engine → facade callback (mirror of {@link EngineCallback}). {@code JMXConnectorServer} owns connection-id
 * tracking and the server-side connection-notification machinery (its {@code protected connectionOpened/
 * Closed/Failed}); the engine observes the per-client lifecycle and routes these events back so the facade can invoke
 * them.
 *
 * <p>Internal SPI — not part of the public OpenDMK API.
 */
public interface ServerConnectionCallback {

    void connectionOpened(String connectionId, String message, Object userData);

    void connectionClosed(String connectionId, String message, Object userData);

    void connectionFailed(String connectionId, String message, Object userData);
}
