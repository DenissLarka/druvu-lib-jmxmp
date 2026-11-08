/*
 * package-info.java — com.druvu.jmxmp.access
 *
 * New in the com.druvu fork (3.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

/**
 * Per-operation authorization for a remotely exposed {@code MBeanServer}, independent of the transport.
 *
 * <p>{@link com.druvu.jmxmp.access.JmxAccessControl} decides; {@link com.druvu.jmxmp.access.PolicyBuilder} is the
 * built-in role-based policy; {@link com.druvu.jmxmp.access.AccessControlledMBeanServer} is the
 * {@code MBeanServerForwarder} a connector installs so that every intercepted operation is checked against the caller's
 * {@link javax.security.auth.Subject} before it reaches the real {@code MBeanServer};
 * {@link com.druvu.jmxmp.access.NamedPrincipal} is a user name as a principal, for a transport that authenticates by
 * name. The module requires {@code java.management} only, so a connector over another transport can reuse it without
 * the JMXMP protocol.
 */
package com.druvu.jmxmp.access;
