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
 * <p>Authorization is by {@link JmxAction verb} and target {@code ObjectName} only. There is deliberately no
 * member-level (attribute-name / operation-name) granularity: parity with the coarse model and the simplest correct
 * rule set.
 *
 * @param action the operation class being attempted; never {@code null}
 * @param target the targeted MBean name, or {@code null} for the untargeted read forms (e.g. {@code getDomains} /
 *     {@code queryNames})
 */
public record JmxAccessRequest(JmxAction action, ObjectName target) {

    public JmxAccessRequest {
        if (action == null) {
            throw new NullPointerException("action");
        }
    }
}
