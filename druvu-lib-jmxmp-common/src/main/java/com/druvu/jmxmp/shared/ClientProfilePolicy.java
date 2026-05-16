/*
 * ClientProfilePolicy.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * A typed, code-only opt-out from the otherwise-mandatory client transport
 * security policy. The server side stays unconditionally locked to
 * { TLS, SASL/PLAIN } + JMXAuthenticator; the client side may be relaxed,
 * but only by passing an instance of this class through the JMX environment
 * map — never via a system property, properties file, or string env entry.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Client-side transport-security policy for outbound JMXMP connections.
 *
 * <p>By default this fork enforces exactly {@code { TLS, SASL/PLAIN }} on both ends. That default is the right one for
 * a <em>server</em> (a deployer must not be able to expose a weak inbound listener) but is needlessly restrictive for a
 * <em>client</em>: connecting outbound to an endpoint is the operator's own informed decision, and a general-purpose
 * JMX client routinely needs to reach existing, often plaintext, production endpoints it does not control. This class
 * is the escape hatch for that case.
 *
 * <p><b>Code-only by construction.</b> The relaxed policy takes effect <em>only</em> when an instance of this class is
 * placed in the JMX environment {@code Map} under {@link #ENV_KEY}:
 *
 * <pre>{@code
 * Map<String, Object> env = new HashMap<>();
 * env.put(ClientProfilePolicy.ENV_KEY, ClientProfilePolicy.unrestricted());
 * JMXConnectorFactory.connect(url, env);
 * }</pre>
 *
 * A {@code -D} system property, a properties file, or any string under {@link #ENV_KEY} can only ever carry a
 * {@link String}, never an instance of this sealed-by-convention type — so the opt-out cannot be flipped by ops
 * tooling, configuration management, or the command line. It requires Java code written against this class. This is the
 * same typed-env pattern the library already uses for {@code jmx.remote.tls.socket.factory} (an
 * {@code SSLSocketFactory} instance) and {@code JMXConnectorServer.AUTHENTICATOR} (a {@code JMXAuthenticator}
 * instance).
 *
 * <p>When no instance is supplied, the secure default ({@link #mandatoryTlsSasl()}) applies — identical to the
 * pre-2.0-escape-hatch behaviour, so existing deployments are unaffected.
 *
 * <p><b>This only relaxes the client.</b> It has no effect on {@code GenericConnectorServer} /
 * {@code JMXMPConnectorServer}, which remain unconditionally {@code TLS SASL/PLAIN} + {@code JMXAuthenticator}.
 *
 * <p>Three shapes:
 *
 * <ul>
 *   <li>{@link #mandatoryTlsSasl()} — the default; the client requires exactly {@code { TLS, SASL/PLAIN }}.
 *   <li>{@link #unrestricted()} — no client-side profile enforcement at all (including none / plaintext); the operator
 *       accepts the consequence. The deserialization allow-list still applies to the client receive path regardless.
 *   <li>{@link #require(String...)} — the negotiated/configured profile set must be exactly the enumerated set
 *       (order-independent, case-insensitive), e.g. {@code require("TLS")} for TLS-only without SASL.
 * </ul>
 */
public final class ClientProfilePolicy {

    /**
     * JMX environment key. The value <strong>must</strong> be a {@code ClientProfilePolicy} instance to relax the
     * client default; a {@code String} (or anything else) under this key is rejected with a {@link SecurityException}
     * rather than silently relaxing or silently ignoring it — the opt-out is code-only by design.
     */
    public static final String ENV_KEY = "com.druvu.jmxmp.client.profilePolicy";

    private enum Kind {
        MANDATORY_TLS_SASL,
        UNRESTRICTED,
        REQUIRE
    }

    private static final ClientProfilePolicy MANDATORY = new ClientProfilePolicy(Kind.MANDATORY_TLS_SASL, Set.of());
    private static final ClientProfilePolicy UNRESTRICTED = new ClientProfilePolicy(Kind.UNRESTRICTED, Set.of());

    private final Kind kind;
    private final Set<String> required;

    private ClientProfilePolicy(Kind kind, Set<String> required) {
        this.kind = kind;
        this.required = required;
    }

    /** The secure default: the client requires exactly {@code { TLS, SASL/PLAIN }} (same as supplying nothing). */
    public static ClientProfilePolicy mandatoryTlsSasl() {
        return MANDATORY;
    }

    /**
     * No client-side profile enforcement — any profile set, including none (plaintext), is accepted. The operator
     * explicitly owns the consequence. The serialization allow-list still guards the client receive path.
     */
    public static ClientProfilePolicy unrestricted() {
        return UNRESTRICTED;
    }

    /**
     * The negotiated/configured client profile set must be exactly {@code profiles} (order-independent,
     * case-insensitive). Example: {@code require("TLS")} permits TLS-only (no SASL) endpoints.
     *
     * @param profiles one or more profile names; must be non-empty with no blank entries
     * @throws IllegalArgumentException if {@code profiles} is null/empty or contains a blank entry
     */
    public static ClientProfilePolicy require(String... profiles) {
        if (profiles == null || profiles.length == 0) {
            throw new IllegalArgumentException("require(...) needs at least one profile name");
        }
        Set<String> set = Arrays.stream(profiles)
                .map(p -> {
                    if (p == null || p.isBlank()) {
                        throw new IllegalArgumentException("require(...) profile names must be non-blank");
                    }
                    return p.trim().toUpperCase(Locale.ROOT);
                })
                .collect(Collectors.toUnmodifiableSet());
        return new ClientProfilePolicy(Kind.REQUIRE, set);
    }

    /** @return true if this policy applies no client-side profile enforcement. */
    boolean isUnrestricted() {
        return kind == Kind.UNRESTRICTED;
    }

    /** @return true if this is the secure default ({@code { TLS, SASL/PLAIN }}). */
    boolean isMandatoryTlsSasl() {
        return kind == Kind.MANDATORY_TLS_SASL;
    }

    /** @return the exact required profile set (upper-cased) for a {@link #require(String...)} policy. */
    Set<String> requiredSet() {
        return required;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof ClientProfilePolicy other)) {
            return false;
        }
        return kind == other.kind && required.equals(other.required);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, required);
    }

    @Override
    public String toString() {
        return switch (kind) {
            case MANDATORY_TLS_SASL -> "ClientProfilePolicy[mandatory TLS SASL/PLAIN]";
            case UNRESTRICTED -> "ClientProfilePolicy[unrestricted]";
            case REQUIRE -> "ClientProfilePolicy[require " + required + "]";
        };
    }
}
