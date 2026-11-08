/*
 * ConnectorThreads.java
 *
 * New in the com.druvu fork (3.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.util;

import java.lang.System.Logger.Level;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The connector's thread pools. Each thread is a daemon named {@code jmxmp-<purpose>-<n>}, carries the context class
 * loader of the thread that created its pool, and logs an exception its job lets escape. An idle thread ends after a
 * minute, so a pool nobody stops leaks nothing.
 *
 * <p>Platform threads on purpose: the connections write their messages inside {@code synchronized} blocks, and on Java
 * 21 to 23 a virtual thread that blocks there pins its carrier (JEP 491 lifted that in Java 24). {@code factory} is the
 * one place to change when the baseline allows virtual threads.
 *
 * @author Deniss Larka <br>
 *     on 08 Nov 2026
 */
public final class ConnectorThreads {

    private static final long IDLE_SECONDS = 60;

    /** One numbering for every pool, so that a thread dump tells two connections apart. */
    private static final AtomicInteger THREAD_NUMBER = new AtomicInteger();

    private static final System.Logger LOG = System.getLogger(ConnectorThreads.class.getName());

    private ConnectorThreads() {}

    /** Runs up to {@code max} jobs at once; the others wait their turn, in order. */
    public static ExecutorService pool(String purpose, int max) {
        ThreadPoolExecutor pool = new ThreadPoolExecutor(
                max, max, IDLE_SECONDS, TimeUnit.SECONDS, new LinkedBlockingQueue<>(), factory(purpose));
        pool.allowCoreThreadTimeOut(true);
        return pool;
    }

    /** Runs one job at a time, in the order they came. */
    public static ExecutorService single(String purpose) {
        return pool(purpose, 1);
    }

    /**
     * Stops a pool for good: no new job, the waiting ones dropped, the running ones interrupted. The calling thread may
     * be one of the pool's (a job that closes its own connection), so its interrupt status is left as it was.
     */
    public static void stop(ExecutorService pool) {
        boolean callerWasInterrupted = Thread.currentThread().isInterrupted();
        pool.shutdownNow();
        if (!callerWasInterrupted) {
            Thread.interrupted();
        }
    }

    private static ThreadFactory factory(String purpose) {
        ClassLoader creatorsLoader = Thread.currentThread().getContextClassLoader();
        return job -> {
            Thread thread = new Thread(job, "jmxmp-" + purpose + "-" + THREAD_NUMBER.incrementAndGet());
            thread.setDaemon(true);
            thread.setContextClassLoader(creatorsLoader);
            thread.setUncaughtExceptionHandler(
                    (t, e) -> LOG.log(Level.WARNING, "Unexpected exception in " + t.getName(), e));
            return thread;
        };
    }
}
