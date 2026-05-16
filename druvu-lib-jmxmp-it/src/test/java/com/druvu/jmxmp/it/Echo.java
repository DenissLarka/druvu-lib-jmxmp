package com.druvu.jmxmp.it;

import java.util.concurrent.atomic.AtomicLong;
import javax.management.MBeanNotificationInfo;
import javax.management.Notification;
import javax.management.NotificationBroadcasterSupport;

/**
 * {@link EchoMBean} implementation. Each {@link #fire()} sends one {@code test.echo} notification with a monotonically
 * increasing sequence number, exercising the JMXMP notification round-trip path.
 */
public class Echo extends NotificationBroadcasterSupport implements EchoMBean {

    private final AtomicLong seq = new AtomicLong();

    @Override
    public String getMessage() {
        return "hello";
    }

    @Override
    public void fire() {
        sendNotification(new Notification("test.echo", this, seq.incrementAndGet(), "ping"));
    }

    @Override
    public void boom() {
        throw new IllegalStateException("boom");
    }

    @Override
    public MBeanNotificationInfo[] getNotificationInfo() {
        return new MBeanNotificationInfo[] {
            new MBeanNotificationInfo(
                    new String[] {"test.echo"}, Notification.class.getName(), "Echo test notification")
        };
    }
}
