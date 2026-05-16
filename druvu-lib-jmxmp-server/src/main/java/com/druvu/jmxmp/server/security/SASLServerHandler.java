/*
 * @(#)file      SASLServerHandler.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.24
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
 * Portions Copyrighted 2026 — com.druvu fork (2.0):
 *   SASL/PLAIN-only, delegated to a mandatory JMXAuthenticator.
 */

package com.druvu.jmxmp.server.security;

import com.druvu.jmxmp.server.generic.ProfileServer;
import com.druvu.jmxmp.shared.*;
import com.druvu.jmxmp.util.*;
import com.druvu.jmxmp.util.ClassLogger;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.ServiceLoader;
import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXPrincipal;
import javax.management.remote.generic.MessageConnection;
import javax.management.remote.message.ProfileMessage;
import javax.management.remote.message.SASLMessage;
import javax.security.auth.Subject;

/**
 * Server side of the JMXMP {@code SASL/PLAIN} profile (2.0).
 *
 * <p><strong>Why a direct PLAIN implementation and not the JDK {@code SaslServer}:</strong> the JDK's
 * {@code com.sun.security.sasl.PlainServer} uses a password-compare callback model — the {@code CallbackHandler} must
 * hand back the <em>expected</em> cleartext password so {@code PlainServer} can compare it. That is fundamentally
 * incompatible with delegating to an opaque {@link JMXAuthenticator} (bcrypt / argon2 / LDAP-bind / OAuth-token
 * validation cannot produce an expected cleartext password). SASL/PLAIN (RFC 4616) is a single client message with no
 * challenge rounds, so the server side is parsed directly here and the {@code authcid}/{@code passwd} pair is handed to
 * the mandatory authenticator. OpenDMK's {@link SASLMessage} profile transport is unchanged.
 *
 * <p>Only PLAIN is accepted. {@code CheckProfiles} already rejects every other mechanism at construction / handshake
 * time; this class refuses non-PLAIN as defence in depth.
 */
public class SASLServerHandler implements ProfileServer {

    // -------------
    // Constructors
    // -------------

    public SASLServerHandler(String profile, Map env) {
        this.profile = profile;
        this.env = env;
    }

    // ---------------------------------------
    // ProfileServer interface implementation
    // ---------------------------------------

    public void initialize(MessageConnection mc, Subject s) throws IOException {
        this.mc = mc;
        this.subject = s;

        // Defence in depth: only SASL/PLAIN. Anything else is a protocol
        // violation now (CheckProfiles already gates this earlier).
        String mechanism = profile.substring(profile.indexOf("SASL/") + 5);
        if (!"PLAIN".equals(mechanism)) {
            throw new IOException(
                    "Unsupported SASL mechanism [" + mechanism + "]; this build supports only SASL/PLAIN.");
        }

        this.authenticator = resolveAuthenticator(env);
    }

    public ProfileMessage produceMessage() {
        int status = authenticated ? SASLMessage.COMPLETE : SASLMessage.CONTINUE;
        SASLMessage challenge = new SASLMessage("PLAIN", status, EMPTY);
        if (logger.traceOn()) {
            logger.trace("produceMessage", ">>>>> SASL server message <<<<<");
            logger.trace("produceMessage", "Profile Name : " + challenge.getProfileName());
            logger.trace("produceMessage", "Status : " + challenge.getStatus());
        }
        return challenge;
    }

    public void consumeMessage(ProfileMessage pm) throws IOException {
        if (!(pm instanceof SASLMessage)) {
            throw new IOException(
                    "Unexpected profile message type: " + pm.getClass().getName());
        }
        SASLMessage response = (SASLMessage) pm;
        if (logger.traceOn()) {
            logger.trace("consumeMessage", ">>>>> SASL client message <<<<<");
            logger.trace("consumeMessage", "Profile Name : " + response.getProfileName());
            logger.trace("consumeMessage", "Status : " + response.getStatus());
        }
        if (response.getStatus() != SASLMessage.CONTINUE) {
            throw new IOException("Unexpected SASL status [" + response.getStatus() + "]");
        }

        // RFC 4616 SASL/PLAIN: authzid NUL authcid NUL passwd
        byte[] blob = response.getBlob();
        if (blob == null) {
            throw new IOException("Empty SASL/PLAIN response");
        }
        int n1 = indexOf(blob, 0, (byte) 0);
        int n2 = (n1 < 0) ? -1 : indexOf(blob, n1 + 1, (byte) 0);
        if (n1 < 0 || n2 < 0) {
            throw new IOException("Malformed SASL/PLAIN response");
        }
        String authzid = new String(blob, 0, n1, StandardCharsets.UTF_8);
        String authcid = new String(blob, n1 + 1, n2 - (n1 + 1), StandardCharsets.UTF_8);
        String passwd = new String(blob, n2 + 1, blob.length - (n2 + 1), StandardCharsets.UTF_8);

        // Delegate validation to the mandatory authenticator. A bad
        // credential throws SecurityException, which propagates so AdminServer
        // sends a HandshakeErrorMessage and closes the connection.
        Subject authSubject = authenticator.authenticate(new String[] {authcid, passwd});
        this.authorizationId = (authzid == null || authzid.isEmpty()) ? authcid : authzid;
        if (authSubject != null) {
            if (subject == null) {
                subject = new Subject();
            }
            subject.getPrincipals().addAll(authSubject.getPrincipals());
        }
        this.authenticated = true;
    }

    public boolean isComplete() {
        return authenticated;
    }

    public Subject activate() throws IOException {
        // PLAIN provides no integrity/privacy layer (auth-only); transport
        // confidentiality is supplied by the mandatory TLS profile, so there
        // are no SASL streams to install here.
        if (subject == null) {
            subject = new Subject();
        }
        subject.getPrincipals().add(new JMXPrincipal(authorizationId));
        return subject;
    }

    public void terminate() throws IOException {
        // No native SASL server resource to dispose.
    }

    public String getName() {
        return profile;
    }

    // ----------------
    // Private methods
    // ----------------

    private static int indexOf(byte[] a, int from, byte v) {
        for (int i = from; i < a.length; i++) {
            if (a[i] == v) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Resolve the mandatory {@link JMXAuthenticator} the same way {@code GenericConnectorServer} does: env entry first,
     * then {@code ServiceLoader}. By the time a SASL message is processed the connector server has already required
     * one, so this should always succeed; it fails loudly rather than silently authenticating no one.
     */
    private static JMXAuthenticator resolveAuthenticator(Map env) throws IOException {
        Object a = (env == null) ? null : env.get(JMXConnectorServer.AUTHENTICATOR);
        if (a instanceof JMXAuthenticator auth) {
            return auth;
        }
        return ServiceLoader.load(JMXAuthenticator.class)
                .findFirst()
                .orElseThrow(() -> new IOException("No JMXAuthenticator available for SASL/PLAIN validation"));
    }

    // ------------------
    // Private variables
    // ------------------

    private static final byte[] EMPTY = new byte[0];

    private Map env;
    private MessageConnection mc;
    private String profile;
    private Subject subject;
    private JMXAuthenticator authenticator;
    private boolean authenticated = false;
    private String authorizationId;
    private static final ClassLogger logger = new ClassLogger("javax.management.remote.misc", "SASLServerHandler");
}
