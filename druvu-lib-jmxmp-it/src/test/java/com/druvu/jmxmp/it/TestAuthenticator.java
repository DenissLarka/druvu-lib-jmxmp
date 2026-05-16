package com.druvu.jmxmp.it;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXPrincipal;
import javax.security.auth.Subject;

/**
 * Minimal map-backed {@link JMXAuthenticator} for the integration tests — mirrors the shape a real consumer would
 * supply. Receives {@code String[]{user, password}} from each SASL/PLAIN flow; returns a {@link Subject} carrying a
 * {@link JMXPrincipal} for the user, or throws {@link SecurityException}.
 */
final class TestAuthenticator implements JMXAuthenticator {

    private final Map<String, String> users;
    final AtomicInteger calls = new AtomicInteger();

    TestAuthenticator(Map<String, String> users) {
        this.users = users;
    }

    @Override
    public Subject authenticate(Object credentials) {
        calls.incrementAndGet();
        if (!(credentials instanceof String[] c) || c.length != 2) {
            throw new SecurityException("Expected String[]{user, password}");
        }
        String user = c[0];
        String pass = c[1];
        String expected = users.get(user);
        if (expected == null || !expected.equals(pass)) {
            throw new SecurityException("Invalid credentials for user [" + user + "]");
        }
        return new Subject(true, Set.of(new JMXPrincipal(user)), Set.of(), Set.of());
    }
}
