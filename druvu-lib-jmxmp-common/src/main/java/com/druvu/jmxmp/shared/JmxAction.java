/*
 * JmxAction.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The coarse JMX authorization verb taxonomy: a deliberately small replacement,
 * for the subset of behaviour JMXMP actually intercepts, of the per-operation
 * model that javax.management.MBeanPermission used to provide before JEP 486
 * permanently removed the Security Manager.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

/**
 * The grantable verb taxonomy for {@link JmxmpAccessControl}: four coarse actions covering every authorizable
 * {@code MBeanServer} operation on an <em>existing</em> MBean.
 *
 * <p>The taxonomy is deliberately small and matches what is actually enforced — there is no per-operation/per-attribute
 * (member-level) matching, and there is no verb for remote MBean lifecycle. Creating, registering, unregistering, or
 * instantiating MBeans remotely, and the deprecated {@code deserialize(...)} forms, are <strong>permanently
 * denied</strong> by the server forwarder: there is no verb that can grant them and
 * {@link JmxmpAccessControl#allowAll()} does not relax them. The only mutation a remote client can ever perform is to
 * an MBean that already exists.
 *
 * <p>Each constant maps to one or more rows in the integration seam that builds a {@link JmxAccessRequest} for it.
 */
public enum JmxAction {

    /**
     * Read-only observation of the management plane: {@code getAttribute(s)} plus all introspection/discovery
     * ({@code queryMBeans}/{@code queryNames}, {@code getMBeanInfo}, {@code getObjectInstance}, {@code isInstanceOf},
     * {@code isRegistered}, {@code getDomains}, {@code getDefaultDomain}, {@code getMBeanCount}). Discovery is folded
     * in because hiding the set of MBeans while permitting reads is security-by-obscurity, not a real control.
     */
    READ,

    /** {@code setAttribute}, {@code setAttributes} — changing attribute values on an existing MBean. */
    WRITE,

    /** {@code invoke} — calling an operation on an existing MBean. The signature is not part of the decision. */
    INVOKE,

    /** {@code addNotificationListener}, {@code removeNotificationListener} — subscribing to an existing MBean. */
    NOTIFY
}
