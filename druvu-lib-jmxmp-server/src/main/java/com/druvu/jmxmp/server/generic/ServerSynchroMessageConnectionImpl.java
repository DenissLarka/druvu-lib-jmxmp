/*
 * @(#)file      ServerSynchroMessageConnectionImpl.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.5
 * @(#)lastedit  07/03/08
 * @(#)build     @BUILD_TAG_PLACEHOLDER@
 *
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2007 Sun Microsystems, Inc. All Rights Reserved.
 *
 * The contents of this file are subject to the terms of either the GNU General
 * Public License Version 2 only ("GPL") or the Common Development and
 * Distribution License("CDDL")(collectively, the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy of the
 * License at http://opendmk.dev.java.net/legal_notices/licenses.txt or in the
 * LEGAL_NOTICES folder that accompanied this code. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file found at
 *     http://opendmk.dev.java.net/legal_notices/licenses.txt
 * or in the LEGAL_NOTICES folder that accompanied this code.
 * Sun designates this particular file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License file that
 * accompanied this code.
 *
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 *
 *       "Portions Copyrighted [year] [name of copyright owner]"
 *
 * Contributor(s):
 *
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding
 *
 *       "[Contributor] elects to include this software in this distribution
 *        under the [CDDL or GPL Version 2] license."
 *
 * If you don't indicate a single choice of license, a recipient has the option
 * to distribute your version of this file under either the CDDL or the GPL
 * Version 2, or to extend the choice of license to its licensees as provided
 * above. However, if you add GPL Version 2 code and therefore, elected the
 * GPL Version 2 license, then the option applies only if the new code is made
 * subject to such option by the copyright holder.
 *
 */

package com.druvu.jmxmp.server.generic;

import com.druvu.jmxmp.internal.DefaultConfig;
import com.druvu.jmxmp.internal.ServerSynchroMessageConnection;
import com.druvu.jmxmp.internal.SynchroCallback;
import com.druvu.jmxmp.server.internal.ServerAdmin;
import com.druvu.jmxmp.server.internal.ServerConfig;
import com.druvu.jmxmp.util.ConnectorThreads;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import javax.management.remote.generic.MessageConnection;
import javax.management.remote.message.CloseMessage;
import javax.management.remote.message.Message;
import javax.security.auth.Subject;

public class ServerSynchroMessageConnectionImpl implements ServerSynchroMessageConnection {

    public ServerSynchroMessageConnectionImpl(MessageConnection mc, Map env) {
        if (mc == null) {
            throw new IllegalArgumentException("Null message connection.");
        }

        this.env = env;

        waitConnectedState = DefaultConfig.getTimeoutForWaitConnectedState(env);

        this.serverAdmin = ServerConfig.getServerAdmin(this.env);

        connection = mc;
    }

    public void connect(Map env) throws IOException {
        synchronized (stateLock) {
            if (state != UNCONNECTED) {
                waitConnected();
                return;
            } else {
                state = CONNECTING;
            }
        }

        connection.connect(env);

        connection = serverAdmin.connectionOpen(connection);

        synchronized (stateLock) {
            if (state != CONNECTING) {
                // closed by another thread
                try {
                    connection.close();
                } catch (Exception e) {
                    // OK Already closed.
                }
                throw new IOException("The connecting is stooped by another thread.");
            }

            state = CONNECTED;
            stateLock.notifyAll();
        }
    }

    public void sendOneWay(Message msg) throws IOException {
        LOG.log(Level.TRACE, "Send a message without response.");

        waitConnected();

        synchronized (connectionLock) {
            connection.writeMessage(msg);
        }
    }

    public void setCallback(SynchroCallback cb) {
        LOG.log(Level.TRACE, "be called.");

        if (callback != null) {
            throw new IllegalArgumentException("The callback has been assigned.");
        }

        if (cb == null) {
            throw new IllegalArgumentException("Null callback.");
        }
        callback = cb;

        // max.threads bounds the requests; the reader runs for the connection's whole life on a thread of its own.
        threads = ConnectorThreads.pool("server-connection", DefaultConfig.getServerMaxThreads(env) + 1);

        reader = new MessageReader();
        threads.execute(reader);
    }

    public String getConnectionId() {
        return connection.getConnectionId();
    }

    public void close() throws IOException {
        LOG.log(Level.TRACE, "Closing this SynchroMessageConnection.");

        synchronized (stateLock) {
            if (state == TERMINATED) {
                return;
            }

            state = TERMINATED;

            LOG.log(Level.TRACE, "Close the callback reader.");
            if (reader != null) {
                reader.stop();
            }

            if (threads != null) {
                ConnectorThreads.stop(threads);

                threads = null;
            }

            LOG.log(Level.TRACE, "Closing the underlying connection.");
            if (connection != null) {
                connection.close();
            }

            serverAdmin.connectionClosed(connection);

            // clean
            LOG.log(Level.TRACE, "Clean all threads waiting theire responses.");

            stateLock.notify();
        }
    }

    /** Returns the underlying asynchronous trasport. */
    public MessageConnection getAsynchroConnection() {
        return connection;
    }

    // ----------------------------------------------
    // private classes
    // ----------------------------------------------

    private class MessageReader implements Runnable {
        public MessageReader() {}

        public void run() {
            try {
                executingThread = Thread.currentThread();

                Message msg;

                while (!stopped()) {
                    LOG.log(Level.TRACE, "Waiting a coming message...");

                    msg = null;

                    try {
                        msg = connection.readMessage();
                    } catch (Exception e) {
                        if (stopped()) {
                            break;
                        }

                        callback.connectionException(e);

                        // if rconnected, a new reader should be created.
                        break;
                    }

                    if (stopped()) {
                        break;
                    }

                    threads.execute(new RemoteJob(msg));

                    if (msg instanceof CloseMessage) {
                        break;
                    }
                }
            } catch (Exception eee) {
                // need to stop
                LOG.log(Level.TRACE, "stops.");
            }

            synchronized (stateLock) {
                executingThreadInterrupted = true;
            }

            LOG.log(Level.TRACE, "ended.");
        }

        public void stop() {
            LOG.log(Level.TRACE, "be called.");

            synchronized (stateLock) {
                if (Thread.currentThread() != executingThread
                        && executingThread != null
                        && !executingThreadInterrupted) {

                    executingThreadInterrupted = true;

                    executingThread.interrupt();
                }
            }

            LOG.log(Level.TRACE, "done.");
        }

        private boolean stopped() {
            synchronized (stateLock) {
                return (state != CONNECTED || executingThreadInterrupted);
            }
        }

        private Thread executingThread;

        // This flag is used to ensure that we interrupt the executingThread
        // only when it is running in this MessageReader object.
        private boolean executingThreadInterrupted = false;
    }

    private class RemoteJob implements Runnable {
        public RemoteJob(Message msg) {
            this.msg = msg;
        }

        public void run() {
            LOG.log(Level.TRACE, "Receive a new request.");

            try {
                Message resp = callback.execute(msg);

                if (resp != null) {
                    synchronized (connectionLock) {
                        connection.writeMessage(resp);
                    }
                }
            } catch (Exception ie) {
                synchronized (stateLock) {
                    if (state != CONNECTED && callback != null) {
                        // inform the callback
                        callback.connectionException(ie);
                    }
                }
            }
        }

        private Message msg;
    }

    public Subject getSubject() {
        return serverAdmin.getSubject(connection);
    }

    // ----------------------------------------------
    // private methods
    // ----------------------------------------------
    private void waitConnected() throws IOException {
        synchronized (stateLock) {
            if (state == CONNECTED) {
                return;
            } else if (state != CONNECTING) {
                throw new IOException("The connection was closed or failed.");
            }

            final long startTime = System.currentTimeMillis();
            long remainingTime = waitConnectedState;

            while (state == CONNECTING && waitConnectedState > 0) {

                try {
                    stateLock.wait(remainingTime);
                } catch (InterruptedException ire) {
                    break;
                }

                remainingTime = waitConnectedState - (System.currentTimeMillis() - startTime);
            }

            if (state != CONNECTED) {
                throw new IOException("The connection is not connected.");
            } else {
                return;
            }
        }
    }

    // ----------------------------------------------
    // private variables
    // ----------------------------------------------
    /** This lock used to ensures no concurrent writes */
    private transient int[] connectionLock = new int[0];

    private transient MessageConnection connection;

    private transient ServerAdmin serverAdmin = null;

    private Map env;

    private transient SynchroCallback callback;
    private transient ExecutorService threads;
    private transient MessageReader reader;

    // state issues
    private static final int UNCONNECTED = 1;
    private static final int CONNECTING = 2;
    private static final int CONNECTED = 3;
    private static final int FAILED = 4;
    private static final int TERMINATED = 5;

    private int state = UNCONNECTED;

    /**
     * Used to control access to the state variable, including ensuring that only one thread manages state transitions.
     */
    private int[] stateLock = new int[0];

    private long waitConnectedState;

    private static final System.Logger LOG = System.getLogger(ServerSynchroMessageConnectionImpl.class.getName());
}
