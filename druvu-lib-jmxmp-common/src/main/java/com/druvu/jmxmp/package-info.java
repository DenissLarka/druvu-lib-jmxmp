/*
 * package-info.java — com.druvu.jmxmp
 *
 * New in the com.druvu fork (3.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

/**
 * The configuration both ends of a JMXMP connection share: {@link com.druvu.jmxmp.ClientProfilePolicy} (what a client
 * accepts from a server), {@link com.druvu.jmxmp.SelectProfiles} (a client's hook into the profile negotiation) and
 * {@link com.druvu.jmxmp.JmxmpSerialFilter} (the deserialization allow-list on the wire).
 *
 * <p>The server-side configuration lives in {@code com.druvu.jmxmp.server}, the access control in
 * {@code com.druvu.jmxmp.access}. Everything under {@code com.druvu.jmxmp.internal} and {@code com.druvu.jmxmp.util} is
 * the protocol's own and is not exported to applications.
 */
package com.druvu.jmxmp;
