/*
 * JmxAccessRequest.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The immutable value object describing a single MBeanServer operation that a
 * JmxmpAccessControl implementation authorizes (or denies).
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

import javax.management.ObjectName;

/**
 * Immutable description of one intercepted {@code MBeanServer} operation, handed to
 * {@link JmxmpAccessControl#checkAccess(javax.security.auth.Subject, JmxAccessRequest)} once per operation.
 *
 * @param action the operation class being attempted; never {@code null}
 * @param target the targeted MBean name, or {@code null} for non-targeted operations (e.g.
 *     {@link JmxAction#GET_DOMAINS} and some {@link JmxAction#GET_CLASSLOADER} / {@link JmxAction#DESERIALIZE} forms)
 * @param member the attribute name (for {@link JmxAction#GET_ATTRIBUTE} / {@link JmxAction#SET_ATTRIBUTE}) or the
 *     operation name (for {@link JmxAction#INVOKE}); {@code null} when not applicable. The {@code invoke} signature is
 *     deliberately <em>not</em> part of the decision (parity with {@code javax.management.MBeanPermission}).
 */
public record JmxAccessRequest(JmxAction action, ObjectName target, String member) {

    public JmxAccessRequest {
        if (action == null) {
            throw new NullPointerException("action");
        }
    }
}
