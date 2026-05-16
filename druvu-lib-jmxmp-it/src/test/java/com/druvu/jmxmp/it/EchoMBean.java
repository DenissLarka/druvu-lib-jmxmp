package com.druvu.jmxmp.it;

/**
 * Trivial MBean used by the round-trip integration test: one read attribute and one operation that emits a
 * notification.
 */
public interface EchoMBean {

    String getMessage();

    /** Fires a single {@code test.echo} notification. */
    void fire();

    /** Always throws — exercises remote exception propagation. */
    void boom();
}
