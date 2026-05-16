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

package com.druvu.jmxmp.shared;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Mandatory, single-shape JMXMP security policy (2.0).
 *
 * <p>A negotiated profile set is accepted <strong>iff</strong> it is exactly {@code {TLS, SASL/PLAIN}}
 * (order-independent, no other entries). Any other combination — empty, plaintext-only, TLS-only, SASL-only, an
 * alternate SASL mechanism (CRAM-MD5, DIGEST-MD5, GSSAPI, EXTERNAL, OAUTHBEARER, …), or an extra entry beyond the
 * allowed set — is rejected with an explicit message naming the offending set.
 *
 * <p>This policy is <strong>not</strong> user-overridable: it replaces the former swappable {@code CheckProfiles}
 * predicate. No environment property bypasses {@link #enforce(List, Map)}.
 */
public final class CheckProfiles {

    /** The only profile set this build accepts (upper-cased, order-independent). */
    private static final Set<String> REQUIRED = Set.of("TLS", "SASL/PLAIN");

    private CheckProfiles() {}

    /**
     * Enforce the mandatory profile policy.
     *
     * @param profiles the negotiated / proposed profile names
     * @param env the connector environment (reserved; no key bypasses the policy)
     * @throws SecurityException if {@code profiles} is not exactly {@code {TLS, SASL/PLAIN}}
     */
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
    }
}
