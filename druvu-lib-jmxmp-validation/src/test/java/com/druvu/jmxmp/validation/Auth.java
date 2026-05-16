/*
 * Validation — minimal map-backed JMXAuthenticator (SASL/PLAIN).
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXPrincipal;
import javax.security.auth.Subject;

final class Auth implements JMXAuthenticator {

    private final Map<String, String> users;
    final AtomicInteger calls = new AtomicInteger();

    Auth(Map<String, String> users) {
        this.users = users;
    }

    @Override
    public Subject authenticate(Object credentials) {
        calls.incrementAndGet();
        if (!(credentials instanceof String[] c) || c.length != 2) {
            throw new SecurityException("Expected String[]{user, password}");
        }
        String expected = users.get(c[0]);
        if (expected == null || !expected.equals(c[1])) {
            throw new SecurityException("Invalid credentials for user [" + c[0] + "]");
        }
        return new Subject(true, Set.of(new JMXPrincipal(c[0])), Set.of(), Set.of());
    }
}
