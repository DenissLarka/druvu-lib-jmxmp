/*
 * package-info.java — com.druvu.jmxmp.spi
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

/**
 * Internal SPI seam between the public-API facades in {@code common} (the
 * {@code javax.management.remote.generic.GenericConnector[Server]} classes, refactored in Phases 6/7) and their engine
 * implementations in the {@code com.druvu.jmxmp.client} / {@code com.druvu.jmxmp.server} modules.
 *
 * <p>The facade loads an engine via {@link java.util.ServiceLoader} across this boundary, so {@code common} has no
 * compile-time edge to client/server.
 *
 * <p><strong>Not part of the public OpenDMK API.</strong> Treated as strictly internal in 2.0; signatures may evolve
 * between minor versions. Notably the provider {@code newEngine} methods type the facade as the JDK super-type
 * ({@code JMXConnector} / {@code JMXConnectorServer}) rather than the concrete facade class — the seam is deliberately
 * decoupled from the concrete facade, which also keeps {@code common} free of any compile dependency on it.
 */
package com.druvu.jmxmp.spi;
