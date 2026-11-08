/*
 * Module descriptor — com.druvu.jmxmp.access
 *
 * New in the com.druvu fork (3.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

/**
 * Per-operation authorization for a remotely exposed {@code MBeanServer}, independent of the transport. Requires
 * {@code java.management} only: never the JMXMP protocol module.
 */
module com.druvu.jmxmp.access {
    requires java.management;

    exports com.druvu.jmxmp.access;
}
