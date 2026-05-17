/*
 * JmxmpServerSecurity.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The server-side unified security builder facade (PLAN-2.0.0 §7.5): a pure
 * assembler that PRODUCES the JMX environment Map with mandatory TLS + SASL/PLAIN
 * + JMXAuthenticator (and optional JmxmpAccessControl) already populated, so the
 * mandatory-ness is enforced at build time instead of as a runtime rejection.
 * It is NOT a connector API — the frozen javax.management.remote.* surface and
 * the §11.9 snapshot are untouched; you still call the unchanged
 * JMXMPConnectorServer constructor with the Map this returns.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXConnectorServer;
import javax.net.ssl.SSLContext;

/**
 * Server-side counterpart to the client's {@link ClientProfilePolicy}: a fluent builder that assembles the JMX
 * environment {@code Map} for a hardened JMXMP server, with mandatory transport security and authentication enforced at
 * <em>build time</em>.
 *
 * <pre>{@code
 * Map<String, Object> env = JmxmpServerSecurity.builder()
 *     .tls(sslContext)                                 // REQUIRED
 *     .authenticator(myJMXAuthenticator)               // REQUIRED
 *     .authorization(JmxmpAccessControl.policy()...)   // optional; omit = authenticated-but-unrestricted
 *     .rawEnv("some.advanced.jsr160.key", value)       // optional escape hatch, last-wins
 *     .build();                                        // IllegalStateException if TLS or authn missing
 * new JMXMPConnectorServer(url, env, mbeanServer);     // unchanged, frozen call
 * }</pre>
 *
 * <p><b>Pure assembler — no security logic of its own.</b> This class only populates env keys. It contains no
 * credential verification, no authenticator implementation, and no "skip auth" convenience: {@link Builder#tls} and
 * {@link Builder#authenticator} are both mandatory and {@link Builder#build()} fails closed if either is missing. The
 * only route to an authentication-only (unrestricted) server is the explicit, code-only
 * {@code .authorization(JmxmpAccessControl.allowAll())}. Authentication itself is supplied by the caller as a
 * {@link JMXAuthenticator} — deliberately <em>not</em> a built-in username/password store, which would be security
 * logic this facade must not own.
 *
 * <p><b>Not a connector API.</b> The output is the standard JSR-160 environment {@code Map}; the frozen
 * {@code javax.management.remote.*} surface is untouched. {@link Builder#rawEnv} is an escape hatch for advanced
 * JSR-160 keys but <strong>cannot set or unset a mandatory key</strong> ({@code jmx.remote.profiles},
 * {@code jmx.remote.tls.socket.factory}, {@link JMXConnectorServer#AUTHENTICATOR}, or
 * {@link JmxmpAccessControl#ENV_KEY} — those have typed setters); attempting to do so fails at {@link Builder#build()}.
 */
public final class JmxmpServerSecurity {

    /** The only profile set this build accepts (see {@code CheckProfiles}). */
    static final String PROFILES = "TLS SASL/PLAIN";

    static final String PROFILES_KEY = "jmx.remote.profiles";
    static final String TLS_SOCKET_FACTORY_KEY = "jmx.remote.tls.socket.factory";

    private JmxmpServerSecurity() {}

    public static Builder builder() {
        return new Builder();
    }

    /** Fluent, single-threaded builder. The {@code Map} it produces is a fresh, caller-owned {@link HashMap}. */
    public static final class Builder {

        private javax.net.ssl.SSLSocketFactory tlsSocketFactory;
        private JMXAuthenticator authenticator;
        private JmxmpAccessControl authorization;
        private final Map<String, Object> raw = new HashMap<>();

        private Builder() {}

        /** REQUIRED. The server's TLS context; its {@code SSLSocketFactory} is handed to the TLS profile. */
        public Builder tls(SSLContext sslContext) {
            Objects.requireNonNull(sslContext, "sslContext");
            this.tlsSocketFactory = sslContext.getSocketFactory();
            return this;
        }

        /** REQUIRED. The SASL/PLAIN authenticator that validates connecting subjects. */
        public Builder authenticator(JMXAuthenticator authenticator) {
            this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
            return this;
        }

        /**
         * Optional. The per-operation authorization control. Omit ⇒ authenticated-but-unrestricted. Pass
         * {@link JmxmpAccessControl#allowAll()} for an explicit, code-only open (authentication-only) server.
         */
        public Builder authorization(JmxmpAccessControl accessControl) {
            this.authorization = Objects.requireNonNull(accessControl, "accessControl");
            return this;
        }

        /** Advanced JSR-160 escape hatch. Applied last-wins; may not target a mandatory key (checked at build). */
        public Builder rawEnv(String key, Object value) {
            Objects.requireNonNull(key, "key");
            raw.put(key, value);
            return this;
        }

        /**
         * Builds the env {@code Map}.
         *
         * @throws IllegalStateException if TLS or the authenticator was not supplied, or if {@link #rawEnv} targets a
         *     mandatory key
         */
        public Map<String, Object> build() {
            if (tlsSocketFactory == null) {
                throw new IllegalStateException("tls(SSLContext) is mandatory");
            }
            if (authenticator == null) {
                throw new IllegalStateException("authenticator(JMXAuthenticator) is mandatory");
            }
            for (String k : raw.keySet()) {
                if (PROFILES_KEY.equals(k)
                        || TLS_SOCKET_FACTORY_KEY.equals(k)
                        || JMXConnectorServer.AUTHENTICATOR.equals(k)
                        || JmxmpAccessControl.ENV_KEY.equals(k)) {
                    throw new IllegalStateException("rawEnv may not set the mandatory/typed key '" + k
                            + "' — use the dedicated builder method");
                }
            }
            Map<String, Object> env = new HashMap<>();
            env.put(PROFILES_KEY, PROFILES);
            env.put(TLS_SOCKET_FACTORY_KEY, tlsSocketFactory);
            env.put(JMXConnectorServer.AUTHENTICATOR, authenticator);
            if (authorization != null) {
                env.put(JmxmpAccessControl.ENV_KEY, authorization);
            }
            env.putAll(raw);
            return env;
        }
    }
}
