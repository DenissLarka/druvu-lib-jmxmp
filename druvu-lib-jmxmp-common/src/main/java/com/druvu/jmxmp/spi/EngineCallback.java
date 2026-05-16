/*
 * EngineCallback.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.spi;

import javax.management.Notification;

/**
 * Engine → facade notification bridge. The facade owns the {@code NotificationBroadcasterSupport} + async dispatch
 * thread; the engine, which observes the connection lifecycle and forwards connector-level events, hands the
 * fully-built {@link Notification} (e.g. {@code JMXConnectionNotification} OPENED/CLOSED/FAILED) back here so the
 * facade can deliver it to consumer-registered connection listeners.
 *
 * <p>Functional by design: the facade passes {@code this::sendNotification} (its {@code protected} method), so that
 * method's visibility — part of the preserved public/protected API surface — is unchanged.
 *
 * <p>Internal SPI — not part of the public OpenDMK API.
 */
@FunctionalInterface
public interface EngineCallback {

    void sendNotification(Notification n);
}
