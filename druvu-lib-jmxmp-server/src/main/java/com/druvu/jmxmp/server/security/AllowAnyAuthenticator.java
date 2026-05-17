/*
 * AllowAnyAuthenticator.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.server.security;

import java.util.Map;
import java.util.Set;
import javax.management.remote.JMXAuthenticator;
import javax.security.auth.Subject;

/**
 * Escape hatch for deliberately-unauthenticated JMXMP deployments (2.0).
 *
 * <p>{@code GenericConnectorServer} refuses to construct without a {@link JMXAuthenticator}. For the rare
 * legitimately-anonymous deployment, supply <em>this</em> authenticator — but it itself refuses to construct unless the
 * environment map explicitly carries
 * {@code com.druvu.jmxmp.security.acknowledge.allow.any=YES_I_ACCEPT_NO_AUTHENTICATION}. The point is to make "I
 * knowingly allow unauthenticated access" a single greppable token in code review, not a silent default.
 *
 * <p>{@link #authenticate(Object)} accepts the {@code String[]{user, password}} the SASL/PLAIN flow supplies and
 * returns a {@link Subject} carrying a {@link NamedPrincipal} for the presented user (or {@code anonymous} when no user
 * was given). The password is not examined.
 */
public final class AllowAnyAuthenticator implements JMXAuthenticator {

    public static final String ACK_KEY = "com.druvu.jmxmp.security.acknowledge.allow.any";
    public static final String ACK_VALUE = "YES_I_ACCEPT_NO_AUTHENTICATION";

    public AllowAnyAuthenticator(Map<String, ?> env) {
        if (env == null || !ACK_VALUE.equals(env.get(ACK_KEY))) {
            throw new SecurityException("AllowAnyAuthenticator requires explicit acknowledgement: set " + ACK_KEY + "="
                    + ACK_VALUE + " in the env map.");
        }
    }

    @Override
    public Subject authenticate(Object credentials) {
        String user = (credentials instanceof String[] c && c.length > 0 && c[0] != null && !c[0].isEmpty())
                ? c[0]
                : "anonymous";
        return new Subject(true, Set.of(new NamedPrincipal(user)), Set.of(), Set.of());
    }
}
