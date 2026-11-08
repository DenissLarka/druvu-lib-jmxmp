/*
 * @(#)file      SASLClientHandler.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.25
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

package com.druvu.jmxmp.client.security;

import com.druvu.jmxmp.client.generic.ProfileClient;
import com.druvu.jmxmp.internal.SocketConnectionIf;
import java.io.IOException;
import java.lang.System.Logger.Level;
import java.net.Socket;
import java.util.Arrays;
import java.util.Map;
import javax.management.remote.generic.MessageConnection;
import javax.management.remote.message.ProfileMessage;
import javax.management.remote.message.SASLMessage;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

/** This class implements the client side SASL profile. */
public class SASLClientHandler implements ProfileClient {

    // -------------
    // Constructors
    // -------------

    public SASLClientHandler(String profile, Map env) {
        this.env = env;
        this.profile = profile;
    }

    // ---------------------------------------
    // ProfileClient interface implementation
    // ---------------------------------------

    public void initialize(MessageConnection mc) throws IOException {

        LOG.log(Level.TRACE, "starts");

        // Check if instance of SocketConnectionIf
        // and retrieve underlying socket
        //
        if (mc instanceof SocketConnectionIf) {
            socket = ((SocketConnectionIf) mc).getSocket();
        } else {
            throw new IOException("Not an instance of SocketConnectionIf");
        }

        // Prepare parameters for creating SASL client
        //
        String mech = profile.substring(profile.indexOf("SASL/") + 5);
        if (!"PLAIN".equals(mech)) {
            throw new IOException("Unsupported SASL mechanism [" + mech + "]; this build supports only SASL/PLAIN.");
        }
        String[] mechs = {"PLAIN"};
        String authzId = (String) env.get("jmx.remote.sasl.authorization.id");
        String server = (String) env.get("jmx.remote.x.sasl.server.name");
        if (server == null) {
            server = socket.getInetAddress().getHostName();
        }
        if (LOG.isLoggable(Level.TRACE)) {
            LOG.log(
                    Level.TRACE,
                    "mech=" + mech + "; mechs=" + Arrays.asList(mechs) + "; authzId=" + authzId + "; server=" + server);
        }

        CallbackHandler cbh = null;
        if (env.containsKey("jmx.remote.sasl.callback.handler")) {
            cbh = (CallbackHandler) env.get("jmx.remote.sasl.callback.handler");
            LOG.log(Level.TRACE, "found callback.handler property: " + cbh);
        } else {
            if (env.containsKey("jmx.remote.credentials")) {
                LOG.log(Level.TRACE, "found jmx.remote.credentials property");
                Object credso = env.get("jmx.remote.credentials");
                if (!(credso instanceof String[])) {
                    LOG.log(Level.TRACE, () -> "...but it is not a String[]: " + credso);
                } else {
                    String[] creds = (String[]) credso;
                    if (creds.length != 2) {
                        LOG.log(Level.TRACE, () -> "...but it does not have 2 " + "elements: " + Arrays.asList(creds));
                    } else {
                        ownHandler = new UserPasswordCallbackHandler(creds[0], creds[1]);
                        cbh = ownHandler;
                    }
                }
            }
        }

        // Create SASL client to use using SASL package
        //
        saslClnt = Sasl.createSaslClient(mechs, authzId, "jmxmp", server, env, cbh);
        if (saslClnt == null) {
            final String detail =
                    "Unable to create SASL client connection for " + "authentication mechanism [" + mech + "]";
            throw new IOException(detail);
        }

        // Retrieve the SASL mechanism in use
        //
        mechanism = saslClnt.getMechanismName();
    }

    public ProfileMessage produceMessage() throws IOException {
        if (initialResponse) {
            blob = saslClnt.hasInitialResponse() ? saslClnt.evaluateChallenge(EMPTY) : EMPTY;
            initialResponse = false;
        }
        SASLMessage response = new SASLMessage(mechanism, SASLMessage.CONTINUE, blob);
        if (LOG.isLoggable(Level.TRACE)) {
            LOG.log(Level.TRACE, ">>>>> SASL client message <<<<<");
            LOG.log(Level.TRACE, "Profile Name : " + response.getProfileName());
            LOG.log(Level.TRACE, "Status : " + response.getStatus());
        }
        return response;
    }

    public void consumeMessage(ProfileMessage pm) throws IOException {
        if (!(pm instanceof SASLMessage)) {
            throw new IOException(
                    "Unexpected profile message type: " + pm.getClass().getName());
        }
        SASLMessage challenge = (SASLMessage) pm;
        if (LOG.isLoggable(Level.TRACE)) {
            LOG.log(Level.TRACE, ">>>>> SASL server message <<<<<");
            LOG.log(Level.TRACE, "Profile Name : " + challenge.getProfileName());
            LOG.log(Level.TRACE, "Status : " + challenge.getStatus());
        }
        if (challenge.getStatus() != SASLMessage.CONTINUE && challenge.getStatus() != SASLMessage.COMPLETE) {
            throw new IOException("Unexpected SASL status [" + challenge.getStatus() + "]");
        }
        if (saslClnt.isComplete() && challenge.getStatus() == SASLMessage.COMPLETE) {
            completed = true;
            return;
        }
        if (saslClnt.isComplete() && challenge.getStatus() != SASLMessage.COMPLETE) {
            throw new IOException("SASL authentication complete despite the server claim for non-completion");
        }
        if (!saslClnt.isComplete() && challenge.getStatus() == SASLMessage.COMPLETE) {
            blob = saslClnt.evaluateChallenge(challenge.getBlob());
            if (saslClnt.isComplete()) {
                completed = true;
                return;
            } else {
                throw new IOException("SASL authentication not complete despite the server claim for completion");
            }
        }
        if (!saslClnt.isComplete() && challenge.getStatus() != SASLMessage.COMPLETE) {
            blob = saslClnt.evaluateChallenge(challenge.getBlob());
        }
    }

    public boolean isComplete() {
        return completed;
    }

    public void activate() throws IOException {
        // PLAIN, the only mechanism this build accepts, negotiates no integrity or privacy layer:
        // the streams stay as they are, inside the TLS the profile list puts first.
        clearOwnPassword();
    }

    public void terminate() throws IOException {
        saslClnt.dispose();
        clearOwnPassword();
    }

    /** The password handed to this handler lives no longer than the exchange that needed it. */
    private void clearOwnPassword() {
        if (ownHandler != null) {
            ownHandler.clearPassword();
        }
    }

    public String getName() {
        return profile;
    }

    // ----------------
    // Private methods
    // ----------------

    /* Predefined CallbackHandler for when we get
    jmx.remote.credentials instead of
    jmx.remote.sasl.callback.handler.  We make a valiant attempt
    not to hold on to the password any longer than we have to, so
    that if someone can snoop our memory (perhaps by examining a
    core dump or the like) they can't fish out passwords.  This
    probably isn't very successful because the password is there
    in the user's Map for at least as long as the handshake
    sequence lasts, and maybe for the entire lifetime of the
    connection.  */
    private static class UserPasswordCallbackHandler implements CallbackHandler {

        UserPasswordCallbackHandler(String user, String password) {
            this.user = user;
            this.pwchars = password.toCharArray();
        }

        public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof NameCallback) {
                    NameCallback ncb = (NameCallback) callbacks[i];
                    ncb.setName(user);
                } else if (callbacks[i] instanceof PasswordCallback) {
                    PasswordCallback pcb = (PasswordCallback) callbacks[i];
                    pcb.setPassword(pwchars);
                } else {
                    throw new UnsupportedCallbackException(callbacks[i]);
                }
            }
        }

        private void clearPassword() {
            if (pwchars != null) {
                for (int i = 0; i < pwchars.length; i++) {
                    pwchars[i] = 0;
                }
                pwchars = null;
            }
        }

        private String user;
        private char[] pwchars;
    }

    // ------------------
    // Private variables
    // ------------------

    private SaslClient saslClnt = null;
    private boolean completed = false;
    private boolean initialResponse = true;
    private byte[] blob = null;
    private Map env = null;
    private Socket socket = null;
    private String mechanism = null;
    private UserPasswordCallbackHandler ownHandler = null;
    private String profile = null;
    private static final byte[] EMPTY = new byte[0];
    private static final System.Logger LOG = System.getLogger(SASLClientHandler.class.getName());
}
