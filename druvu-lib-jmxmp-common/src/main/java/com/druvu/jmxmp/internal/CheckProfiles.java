/*
 * @(#)file      CheckProfiles.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.4
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

package com.druvu.jmxmp.internal;

import com.druvu.jmxmp.ClientProfilePolicy;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * JMXMP security policy (2.0).
 *
 * <p><b>Server side — mandatory, single-shape, no escape hatch.</b> {@link #enforce(List, Map)} /
 * {@link #enforceSpec(String, Map)} accept a profile set <strong>iff</strong> it is exactly {@code {TLS, SASL/PLAIN}}
 * (no other entries; the order is checked apart, TLS first). Any other combination — empty, plaintext-only, TLS-only,
 * SASL-only, an alternate SASL mechanism (CRAM-MD5, DIGEST-MD5, GSSAPI, EXTERNAL, OAUTHBEARER, …), or an extra entry
 * beyond the allowed set — is rejected with an explicit message naming the offending set. These are
 * <strong>not</strong> user-overridable; no environment property bypasses them. They are called from the server gates
 * only. Note: the server connector defaults an <em>absent</em> profile to {@code {TLS, SASL/PLAIN}} before calling
 * these (so a caller supplying only a {@code JMXAuthenticator} still gets a secure listener); a present-but-different
 * set is still rejected here.
 *
 * <p><b>Client side — secure by default, typed-API escape hatch.</b> {@link #enforceClient(List, Map)} /
 * {@link #enforceClientSpec(String, Map)} apply the same {@code {TLS, SASL/PLAIN}} default, but honour a
 * {@link ClientProfilePolicy} instance supplied under {@link ClientProfilePolicy#ENV_KEY}: {@code unrestricted()}
 * disables the set check, {@code require(...)} pins an exact alternate set. The opt-out is reachable only from code
 * that constructs a {@code ClientProfilePolicy} — a {@code String} (or anything else) under that key is rejected, never
 * silently honoured or ignored — so it cannot be flipped via a system property, properties file, or the command line.
 * The threat model is deliberately asymmetric: a server must not be relaxable (it would expose a weak inbound
 * listener), an outbound client connection is the operator's own informed choice.
 *
 * <p><b>Both sides — TLS first.</b> The set says which profiles run, not in which order, and the client runs them in
 * the order of its list: {@code SASL/PLAIN TLS} is the right set and still sends the password over the plain socket. So
 * TLS, when a list holds it, must come first ({@link #enforceTlsFirst(List)}), under every client policy; and the
 * server refuses any profile a client starts before TLS is active ({@link #enforceTlsActive(String, boolean)}).
 */
public final class CheckProfiles {

    /** The profile that must run first: every profile after it travels inside it. */
    private static final String TLS = "TLS";

    /** The only profile set this build accepts (upper-cased; the order is checked apart, TLS first). */
    private static final Set<String> REQUIRED = Set.of(TLS, "SASL/PLAIN");

    private CheckProfiles() {}

    /**
     * Parse and enforce a {@code jmx.remote.profiles} spec string. A {@code null} or blank spec is an
     * {@link IllegalArgumentException} (the caller never configured profiles at all); a present-but-wrong spec is a
     * {@link SecurityException} via {@link #enforce(List, Map)}.
     *
     * @param spec the raw whitespace-separated profile spec, or {@code null}
     * @param env the connector environment
     */
    public static void enforceSpec(String spec, Map<String, ?> env) {
        if (spec == null || spec.isBlank()) {
            throw new IllegalArgumentException("JMXMP requires jmx.remote.profiles=\"TLS SASL/PLAIN\"");
        }
        enforce(Arrays.asList(spec.trim().split("\\s+")), env);
    }

    /**
     * Enforce the mandatory profile policy.
     *
     * @param profiles the negotiated / proposed profile names
     * @param env the connector environment (reserved; no key bypasses the policy)
     * @throws SecurityException if {@code profiles} is not exactly {@code {TLS, SASL/PLAIN}} with TLS first
     */
    public static void enforce(List<String> profiles, Map<String, ?> env) {
        if (profiles == null || profiles.isEmpty()) {
            throw new SecurityException("JMXMP requires jmx.remote.profiles=\"TLS SASL/PLAIN\" (got: empty)");
        }
        Set<String> got =
                profiles.stream().map(p -> p.toUpperCase(Locale.ROOT)).collect(Collectors.toUnmodifiableSet());
        if (!got.equals(REQUIRED)) {
            throw new SecurityException("JMXMP supports exactly { TLS, SASL/PLAIN } in this build. Got: " + got
                    + ". Other SASL mechanisms (CRAM-MD5, DIGEST-MD5, GSSAPI, EXTERNAL, OAUTHBEARER)"
                    + " are not supported.");
        }
        enforceTlsFirst(profiles);
    }

    /**
     * TLS, when a profile list holds it, comes first and only there. Profiles run in list order, so in
     * {@code SASL/PLAIN TLS} the SASL credentials would cross the plain socket before TLS starts. No client policy
     * relaxes this: no profile this connector speaks needs to run before TLS.
     *
     * @param profiles the profile names in the order they run, or {@code null} for none
     * @throws SecurityException if TLS is in the list anywhere but first
     */
    public static void enforceTlsFirst(List<String> profiles) {
        if (profiles == null) {
            return;
        }
        // trimmed, as the set check trims: a name is the same name for both checks
        boolean tlsAfterAnother = profiles.stream().skip(1).map(String::trim).anyMatch(TLS::equalsIgnoreCase);
        if (tlsAfterAnother) {
            throw new SecurityException("JMXMP runs TLS first, so that no profile runs over the plain socket. Got: "
                    + profiles + ". Put TLS first in jmx.remote.profiles, e.g. \"TLS SASL/PLAIN\".");
        }
    }

    /**
     * The server's side of {@link #enforceTlsFirst(List)}, checked as each profile starts. The server mandates TLS, so
     * until TLS is active on a connection the only profile a client may start is TLS. A client that sends SASL/PLAIN
     * first has already put its password on the plain socket; the server cannot undo that, but it refuses before any
     * credential is checked, so such a client never gets a session.
     *
     * @param profile the profile the client starts
     * @param tlsActive whether TLS already protects the connection
     * @throws SecurityException if a profile other than TLS starts before TLS is active
     */
    public static void enforceTlsActive(String profile, boolean tlsActive) {
        if (!tlsActive && !TLS.equalsIgnoreCase(profile)) {
            throw new SecurityException("JMXMP runs TLS first, but the client started " + profile
                    + " before TLS. Set jmx.remote.profiles=\"TLS SASL/PLAIN\" on the client.");
        }
    }

    /**
     * Resolve the client-side policy from the env map. Absent → the secure default. Present and a
     * {@link ClientProfilePolicy} → that policy. Present and anything else (e.g. a {@code String} injected via a system
     * property) → {@link SecurityException}: the opt-out is code-only by design and a non-typed value here is a
     * misconfiguration, not a silent relaxation and not a silent ignore (fail closed, with a diagnostic).
     */
    private static ClientProfilePolicy resolveClientPolicy(Map<String, ?> env) {
        Object v = (env == null) ? null : env.get(ClientProfilePolicy.ENV_KEY);
        if (v == null) {
            return ClientProfilePolicy.mandatoryTlsSasl();
        }
        if (v instanceof ClientProfilePolicy p) {
            return p;
        }
        throw new SecurityException("'" + ClientProfilePolicy.ENV_KEY + "' must be a "
                + ClientProfilePolicy.class.getName() + " instance set programmatically; got "
                + v.getClass().getName() + ". The client transport-security policy cannot be relaxed via a system"
                + " property, properties file, or string env entry.");
    }

    /**
     * Client counterpart of {@link #enforceSpec(String, Map)}, the early, fail-fast check at connector construction /
     * {@code connect()}: the {@link ClientProfilePolicy} under {@link ClientProfilePolicy#ENV_KEY} (the secure default
     * when absent) checks the configured spec, then {@link #enforceTlsFirst(List)} its order.
     *
     * @param spec the raw whitespace-separated {@code jmx.remote.profiles} spec, or {@code null}
     * @param env the connector environment (carries the optional {@link ClientProfilePolicy})
     */
    public static void enforceClientSpec(String spec, Map<String, ?> env) {
        resolveClientPolicy(env).checkSpec(spec);
        if (spec != null && !spec.isBlank()) {
            enforceTlsFirst(Arrays.asList(spec.trim().split("\\s+")));
        }
    }

    /**
     * Client counterpart of {@link #enforce(List, Map)}, the post-negotiation check on the actual negotiated profile
     * set: the {@link ClientProfilePolicy} under {@link ClientProfilePolicy#ENV_KEY} (the secure default when absent)
     * checks it, then {@link #enforceTlsFirst(List)} its order.
     *
     * @param profiles the negotiated / configured profile names, in the order they run
     * @param env the connector environment (carries the optional {@link ClientProfilePolicy})
     */
    public static void enforceClient(List<String> profiles, Map<String, ?> env) {
        resolveClientPolicy(env).check(profiles);
        enforceTlsFirst(profiles);
    }
}
