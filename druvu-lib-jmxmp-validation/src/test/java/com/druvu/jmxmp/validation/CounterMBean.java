/*
 * Validation — test MBean: one read attribute, an ordered-burst
 * notification emitter, and an always-throwing op (exception
 * propagation across the modular boundary).
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

public interface CounterMBean {

    String getMessage();

    /** Fires {@code n} {@code test.count} notifications with sequence 1..n, in order. */
    void burst(int n);

    /** Always throws — exercises remote-exception propagation over JMXMP. */
    void boom();
}
