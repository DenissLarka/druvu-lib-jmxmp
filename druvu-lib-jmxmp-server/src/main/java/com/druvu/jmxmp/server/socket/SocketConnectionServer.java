/*
 * @(#)file      SocketConnectionServer.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.18
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

package com.druvu.jmxmp.server.socket;

import com.druvu.jmxmp.shared.DefaultConfig;
import com.druvu.jmxmp.shared.SocketConnection;
import com.druvu.jmxmp.util.ClassLogger;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.Map;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.generic.MessageConnection;
import javax.management.remote.generic.MessageConnectionServer;
import javax.management.remote.jmxmp.JMXMPConnectorServer;

/** This class uses a Tcp Server Socket to realize a JMX connection server */
public class SocketConnectionServer implements MessageConnectionServer {

    public SocketConnectionServer(JMXServiceURL addr, Map env) throws IOException {

        if (logger.traceOn()) {
            logger.trace("constructor", "Constructs a SocketConnectionServer on " + addr);
        }

        if (addr == null) {
            throw new NullPointerException("Null address.");
        }

        if (!DEFAULT_PROTOCOL.equalsIgnoreCase(addr.getProtocol())) {
            throw new MalformedURLException("Unknown protocol: " + addr.getProtocol());
        }

        String wildcardS = null;
        if (env != null) {
            wildcardS = (String) env.get(JMXMPConnectorServer.SERVER_ADDRESS_WILDCARD);
        }

        wildcard = (wildcardS == null) ? true : wildcardS.equalsIgnoreCase("true");

        this.addr = addr;
    }

    // implements MessageConnectionServer interface

    public void start(Map env) throws IOException {
        if (logger.traceOn()) {
            logger.trace("start", "Starts the server now.");
        }

        Map newEnv = new HashMap();
        if (this.env != null) {
            newEnv.putAll(this.env);
        }
        if (env != null) {
            newEnv.putAll(env);
        }

        final int port = addr.getPort();
        String host = addr.getHost();
        if (host.equals("")) {
            host = InetAddress.getLocalHost().getHostName();
        }

        /* In the wildcard case, the following socket creation just
         * serves to check that the address in the URL is a valid
         * local address. */
        if (wildcard) {
            ss = new ServerSocket(0, DEFAULT_BACKLOG, InetAddress.getByName(host));
            ss.close();
        }

        if (DefaultConfig.getServerReuseAddress(newEnv)) {
            ss = new ServerSocket();
            ss.setReuseAddress(true);
            SocketAddress sockAddr = wildcard ? new InetSocketAddress(port) : new InetSocketAddress(host, port);
            ss.bind(sockAddr, DEFAULT_BACKLOG);
        } else if (wildcard) {
            ss = new ServerSocket(port, DEFAULT_BACKLOG);
        } else {
            ss = new ServerSocket(port, DEFAULT_BACKLOG, InetAddress.getByName(host));
        }

        addr = new JMXServiceURL(DEFAULT_PROTOCOL, host, ss.getLocalPort());

        this.env = newEnv;
    }

    public MessageConnection accept() throws IOException {
        if (logger.traceOn()) {
            logger.trace("accept", "Waiting a new connection...");
        }

        MessageConnection mc = new SocketConnection(ss.accept());
        return mc;
    }

    public void stop() throws IOException {
        if (logger.traceOn()) {
            logger.trace("stop", "Stops the server now.");
        }

        if (ss != null) {
            ss.close();
        }
    }

    public JMXServiceURL getAddress() {
        return addr;
    }

    // private variables
    private ServerSocket ss;
    private JMXServiceURL addr;
    private boolean wildcard;
    private Map env;

    private static final String DEFAULT_PROTOCOL = "jmxmp";
    private static final int DEFAULT_BACKLOG = 100;

    private final ClassLogger logger = new ClassLogger("javax.management.remote.misc", "SocketConnectionServer");
}
