package com.druvu.jmxmp.it;

/** Test MBean that reports the caller identity its method observes via {@code Subject.current()}. */
public interface CallerMBean {

    /**
     * Comma-joined principal names from {@code Subject.current()}, or {@code "<none>"} if there is no current subject.
     */
    String whoAmI();
}
