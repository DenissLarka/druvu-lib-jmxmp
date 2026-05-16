/*
 * Validation — {@link CounterMBean} implementation.
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import java.util.concurrent.atomic.AtomicLong;
import javax.management.MBeanNotificationInfo;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;

public class Counter extends NotificationBroadcasterSupport implements CounterMBean {

    private final AtomicLong seq = new AtomicLong();

    @Override
    public String getMessage() {
        return "hello";
    }

    @Override
    public void burst(int n) {
        for (int i = 0; i < n; i++) {
            sendNotification(new Notification("test.count", this, seq.incrementAndGet(), "tick"));
        }
    }

    @Override
    public void boom() {
        throw new IllegalStateException("boom");
    }

    @Override
    public MBeanNotificationInfo[] getNotificationInfo() {
        return new MBeanNotificationInfo[] {
            new MBeanNotificationInfo(
                    new String[] {"test.count"}, Notification.class.getName(), "ordered burst notification")
        };
    }
}
