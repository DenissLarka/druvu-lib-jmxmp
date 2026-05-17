/*
 * JmxAction.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The fine-grained JMX authorization action taxonomy: a replacement, for the
 * subset of behaviour JMXMP actually intercepts, of the per-operation model
 * that javax.management.MBeanPermission used to provide before JEP 486
 * permanently removed the Security Manager.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

/**
 * The permission taxonomy for {@link JmxmpAccessControl}: one constant per intercepted {@code MBeanServer} operation
 * group, with names mirroring the action vocabulary of {@code javax.management.MBeanPermission} (familiar,
 * battle-tested, and the exact model JEP&nbsp;486 removed from the platform).
 *
 * <p>Each constant maps 1:1 to the row in the integration seam that builds a {@link JmxAccessRequest} for it. The
 * "read-ish" cluster — {@link #GET_ATTRIBUTE}, {@link #GET_MBEAN_INFO}, {@link #GET_OBJECT_INSTANCE},
 * {@link #GET_DOMAINS}, {@link #QUERY}, {@link #GET_CLASSLOADER}, {@link #DESERIALIZE} — observes; the rest mutate. The
 * legacy {@code invoke}-as-write conflation is intentionally gone: {@link #INVOKE} is its own action.
 */
public enum JmxAction {

    /** {@code getAttribute}, {@code getAttributes} — targeted by ObjectName + attribute member. */
    GET_ATTRIBUTE,

    /** {@code setAttribute}, {@code setAttributes} — targeted by ObjectName + attribute member. */
    SET_ATTRIBUTE,

    /** {@code invoke} — targeted by ObjectName + operation member; the signature is not part of the decision. */
    INVOKE,

    /** {@code createMBean}, {@code registerMBean} — targeted by ObjectName. */
    REGISTER_MBEAN,

    /** {@code unregisterMBean} — targeted by ObjectName. */
    UNREGISTER_MBEAN,

    /** {@code instantiate} — class instantiation (not an MBean registration). */
    INSTANTIATE,

    /** {@code addNotificationListener} — targeted by ObjectName. */
    ADD_NOTIFICATION_LISTENER,

    /** {@code removeNotificationListener} — targeted by ObjectName. */
    REMOVE_NOTIFICATION_LISTENER,

    /** {@code getMBeanInfo} — targeted by ObjectName. */
    GET_MBEAN_INFO,

    /** {@code getObjectInstance}, {@code isInstanceOf} — targeted by ObjectName. */
    GET_OBJECT_INSTANCE,

    /** {@code getClassLoader}, {@code getClassLoaderFor}, {@code getClassLoaderRepository} — ObjectName nullable. */
    GET_CLASSLOADER,

    /** {@code queryMBeans}, {@code queryNames} — coarse: a single grant, not per-discovered-name (see SPI doc). */
    QUERY,

    /** {@code getDomains}, {@code getMBeanCount} — coarse: not targeted. */
    GET_DOMAINS,

    /** {@code deserialize(...)} overloads — ObjectName nullable. */
    DESERIALIZE
}
