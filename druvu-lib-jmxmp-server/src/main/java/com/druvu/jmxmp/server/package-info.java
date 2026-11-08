/*
 * package-info.java — com.druvu.jmxmp.server
 *
 * New in the com.druvu fork (3.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

/**
 * What an application configures to expose its {@code MBeanServer} over JMXMP.
 *
 * <p>{@link com.druvu.jmxmp.server.JmxmpServerSecurity} builds the environment map (TLS, the authenticator, the
 * optional access control) for {@code JMXConnectorServerFactory.newJMXConnectorServer};
 * {@link com.druvu.jmxmp.server.AllowAnyAuthenticator} is the explicitly acknowledged no-authentication authenticator
 * for development. The engine behind them is not exported.
 */
package com.druvu.jmxmp.server;
