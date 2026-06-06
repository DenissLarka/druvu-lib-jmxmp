/*
 * @(#)file      TLSServerHandler.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.27
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

package com.druvu.jmxmp.server.security;

import com.druvu.jmxmp.server.generic.ProfileServer;
import com.druvu.jmxmp.shared.SocketConnectionIf;
import com.druvu.jmxmp.util.ClassLogger;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.StringTokenizer;
import javax.management.remote.generic.MessageConnection;
import javax.management.remote.message.ProfileMessage;
import javax.management.remote.message.TLSMessage;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;

/** This class implements the server side TLS profile. */
public class TLSServerHandler implements ProfileServer {

    // JSSE has been bundled in the JRE since J2SE 1.4. The pre-1.4 shims —
    // a bundledJSSE flag plus reflective SSLSession/SSLSocket method
    // wrappers — are removed; callers invoke the SSL* methods directly.

    // -------------
    // Constructors
    // -------------

    public TLSServerHandler(String profile, Map env) {
        this.profile = profile;
        this.env = env;
    }

    // ---------------------------------------
    // ProfileServer interface implementation
    // ---------------------------------------

    public void initialize(MessageConnection mc, Subject s) throws IOException {

        this.mc = mc;
        this.subject = s;

        // Check if instance of SocketConnectionIf
        // and retrieve underlying socket
        //
        Socket socket = null;
        if (mc instanceof SocketConnectionIf) {
            socket = ((SocketConnectionIf) mc).getSocket();
        } else {
            throw new IOException("Not an instance of SocketConnectionIf");
        }

        // Get SSLSocketFactory
        //
        SSLSocketFactory ssf = (SSLSocketFactory) env.get("jmx.remote.tls.socket.factory");

        if (ssf == null) {
            // druvu 2.0.0: no TLS socket factory configured. Honor an explicitly configured JSSE default
            // (-Djavax.net.ssl.keyStore=...) if present; otherwise generate an ephemeral self-signed identity so the
            // mandatory-TLS listener is encrypted out of the box (opportunistic, STARTTLS-style) rather than failing
            // or — as classic plaintext JMXMP does — exposing everything in clear. This is encryption only, not
            // server-identity / MITM protection; set jmx.remote.tls.socket.factory for that. See SelfSignedTls.
            if (System.getProperty("javax.net.ssl.keyStore") != null) {
                ssf = (SSLSocketFactory) SSLSocketFactory.getDefault();
            } else {
                ssf = SelfSignedTls.socketFactory();
            }
        }

        String hostname = socket.getInetAddress().getHostName();
        int port = socket.getPort();
        if (logger.traceOn()) {
            logger.trace("initialize", "TLS: Hostname = " + hostname);
            logger.trace("initialize", "TLS: Port = " + port);
        }
        ts = (SSLSocket) ssf.createSocket(socket, hostname, port, true);

        // Set the SSLSocket Client Mode
        //
        ts.setUseClientMode(false);
        if (logger.traceOn()) {
            logger.trace("initialize", "TLS: Socket Client Mode = " + ts.getUseClientMode());
        }

        // Set the SSLSocket Enabled Protocols
        //
        {
            String enabledProtocols = (String) env.get("jmx.remote.tls.enabled.protocols");
            // druvu 2.0.0 hardening: default to TLS 1.3 only when unset; an explicit
            // jmx.remote.tls.enabled.protocols value still overrides verbatim.
            if (enabledProtocols == null) {
                enabledProtocols = "TLSv1.3";
            }
            StringTokenizer st = new StringTokenizer(enabledProtocols, " ");
            int tokens = st.countTokens();
            String enabledProtocolsList[] = new String[tokens];
            for (int i = 0; i < tokens; i++) {
                enabledProtocolsList[i] = st.nextToken();
            }
            ts.setEnabledProtocols(enabledProtocolsList);
            if (logger.traceOn()) {
                logger.trace("initialize", "TLS: Enabled Protocols");
                String[] enabled_p = ts.getEnabledProtocols();
                if (enabled_p != null) {
                    StringBuffer str_buffer = new StringBuffer();
                    for (int i = 0; i < enabled_p.length; i++) {
                        str_buffer.append(enabled_p[i]);
                        if (i + 1 < enabled_p.length) {
                            str_buffer.append(", ");
                        }
                    }
                    logger.trace("initialize", "TLS: [" + str_buffer + "]");
                } else {
                    logger.trace("initialize", "TLS: []");
                }
            }
        }

        // Set the SSLSocket Enabled Cipher Suites
        //
        String enabledCipherSuites = (String) env.get("jmx.remote.tls.enabled.cipher.suites");
        if (enabledCipherSuites != null) {
            StringTokenizer st = new StringTokenizer(enabledCipherSuites, " ");
            int tokens = st.countTokens();
            String enabledCipherSuitesList[] = new String[tokens];
            for (int i = 0; i < tokens; i++) {
                enabledCipherSuitesList[i] = st.nextToken();
            }
            ts.setEnabledCipherSuites(enabledCipherSuitesList);
        }
        if (logger.traceOn()) {
            logger.trace("initialize", "TLS: Enabled Cipher Suites");
            String[] enabled_cs = ts.getEnabledCipherSuites();
            if (enabled_cs != null) {
                StringBuffer str_buffer = new StringBuffer();
                for (int i = 0; i < enabled_cs.length; i++) {
                    str_buffer.append(enabled_cs[i]);
                    if (i + 1 < enabled_cs.length) {
                        str_buffer.append(", ");
                    }
                }
                logger.trace("initialize", "TLS: [" + str_buffer + "]");
            } else {
                logger.trace("initialize", "TLS: []");
            }
        }

        // Configures the socket to require client authentication
        //
        String needClientAuth = (String) env.get("jmx.remote.tls.need.client.authentication");
        if (needClientAuth != null) {
            ts.setNeedClientAuth(Boolean.valueOf(needClientAuth).booleanValue());
        }
        if (logger.traceOn()) {
            logger.trace("initialize", "TLS: Socket Need Client Authentication = " + ts.getNeedClientAuth());
        }

        // Configures the socket to request client authentication
        //
        {
            String wantClientAuth = (String) env.get("jmx.remote.tls.want.client.authentication");
            if (wantClientAuth != null) {
                ts.setWantClientAuth(Boolean.parseBoolean(wantClientAuth));
            }
            if (logger.traceOn()) {
                logger.trace("initialize", "TLS: Socket Want Client Authentication = " + ts.getWantClientAuth());
            }
        }
    }

    public ProfileMessage produceMessage() {
        TLSMessage tlspm = new TLSMessage(TLSMessage.PROCEED);
        if (logger.traceOn()) {
            logger.trace("produceMessage", ">>>>> TLS server message <<<<<");
            logger.trace("produceMessage", "Profile Name : " + tlspm.getProfileName());
            logger.trace("produceMessage", "Status : " + tlspm.getStatus());
        }
        completed = true;
        return tlspm;
    }

    public void consumeMessage(ProfileMessage pm) throws IOException {
        if (!(pm instanceof TLSMessage)) {
            throw new IOException(
                    "Unexpected profile message type: " + pm.getClass().getName());
        }
        TLSMessage tlspm = (TLSMessage) pm;
        if (logger.traceOn()) {
            logger.trace("consumeMessage", ">>>>> TLS client message <<<<<");
            logger.trace("consumeMessage", "Profile Name : " + tlspm.getProfileName());
            logger.trace("consumeMessage", "Status : " + tlspm.getStatus());
        }
        if (tlspm.getStatus() != TLSMessage.READY) {
            throw new IOException("Unexpected TLS status [" + tlspm.getStatus() + "]");
        }
    }

    public boolean isComplete() {
        return completed;
    }

    public Subject activate() throws IOException {
        if (logger.traceOn()) {
            logger.trace("activate", ">>>>> TLS handshake <<<<<");
            logger.trace("activate", "TLS: Start TLS Handshake");
        }
        ts.startHandshake();
        SSLSession session = ts.getSession();
        if (session != null) {
            if (logger.traceOn()) {
                logger.trace("activate", "TLS: getCipherSuite = " + session.getCipherSuite());
                logger.trace("activate", "TLS: getPeerHost = " + session.getPeerHost());
                {
                    logger.trace("activate", "TLS: getProtocol = " + session.getProtocol());
                }
            }
            // Retrieve the subject distinguished name from the client's
            // certificate, if client authentication was carried out.
            //
            try {
                final Certificate[] certificate = session.getPeerCertificates();
                if (certificate != null && certificate[0] != null && certificate[0] instanceof X509Certificate cert) {
                    // getSubjectX500Principal() returns a java.security.Principal
                    // (X500Principal) natively since J2SE 1.4 — no reflective
                    // reconstruction needed.
                    final Principal principal = cert.getSubjectX500Principal();
                    if (subject == null) {
                        subject = new Subject();
                    }
                    subject.getPrincipals().add(principal);
                    logger.trace("activate", "TLS: Client Authentication OK!" + " SubjectDN = " + principal);
                } else {
                    logger.trace("activate", "TLS: No Client Authentication");
                }
            } catch (SSLPeerUnverifiedException e) {
                logger.trace("activate", "TLS: No Client Authentication: " + e.getMessage());
            }
            logger.trace("activate", "TLS: Finish TLS Handshake");
        }

        // Set new TLS socket in MessageConnection
        //
        ((SocketConnectionIf) mc).setSocket(ts);

        // Return given Subject
        //
        return subject;
    }

    public void terminate() throws IOException {}

    public String getName() {
        return profile;
    }

    // --------------------
    // Protected variables
    // --------------------

    protected SSLSocket ts = null;

    // ------------------
    // Private variables
    // ------------------

    private boolean completed = false;
    private Map env = null;
    private MessageConnection mc = null;
    private String profile = null;
    private Subject subject = null;
    private static final ClassLogger logger = new ClassLogger("javax.management.remote.misc", "TLSServerHandler");
}
