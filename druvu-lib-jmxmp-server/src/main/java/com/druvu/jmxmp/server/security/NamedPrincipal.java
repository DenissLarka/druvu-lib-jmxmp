/*
 * NamedPrincipal.java
 *
 * Added in the com.druvu fork (2.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.server.security;

import com.druvu.jmxmp.shared.*;
import com.druvu.jmxmp.util.*;
import java.io.Serializable;
import java.security.Principal;
import java.util.Objects;

/**
 * Minimal immutable {@link Principal} that wraps a username string. Used by {@link AllowAnyAuthenticator} to populate
 * the returned {@link javax.security.auth.Subject}.
 */
final class NamedPrincipal implements Principal, Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;

    NamedPrincipal(String name) {
        this.name = Objects.requireNonNull(name, "name");
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof NamedPrincipal p) && name.equals(p.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public String toString() {
        return "NamedPrincipal[" + name + "]";
    }
}
