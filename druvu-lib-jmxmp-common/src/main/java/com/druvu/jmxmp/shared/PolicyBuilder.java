/*
 * PolicyBuilder.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The fluent builder for the single built-in JmxmpAccessControl policy:
 * programmatic, typed, default-deny RBAC. No file format.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.security.auth.Subject;

/**
 * Fluent builder for the one built-in {@link JmxmpAccessControl}: programmatic, typed, <strong>strict
 * default-deny</strong> RBAC. Obtain it via {@link JmxmpAccessControl#policy()}.
 *
 * <p>Model (per the signed-off design):
 *
 * <ul>
 *   <li><b>Roles</b> are named allow-lists. {@link #allow(JmxAction, String)} grants an action on an {@code ObjectName}
 *       pattern; {@link #allow(JmxAction)} grants an action with no target constraint (the right form for the
 *       untargeted {@link JmxAction#READ} forms such as {@code queryNames} / {@code getDomains}).
 *       {@link #inherit(String)} composes another role's grants into the current one.
 *   <li><b>Targets</b> are {@code ObjectName} patterns; a request matches when {@code new ObjectName(pattern)
 *       .apply(requestTarget)} is true. The shorthand {@code "*"} means "any name".
 *   <li><b>Principals</b> map by <em>name</em> ({@link java.security.Principal#getName()}) to roles via
 *       {@link #principal(String)} + {@link #grantedRoles(String...)}. A subject is allowed iff <em>any</em> of its
 *       principals' granted roles (inheritance resolved) allows the request — RBAC union semantics.
 * </ul>
 *
 * <p><b>Deliberate simplifications:</b> the verb taxonomy is coarse ({@code READ}/{@code WRITE}/{@code INVOKE}/
 * {@code NOTIFY}); discovery folds into {@code READ}; there is no member-level (attribute-/operation-name) matching;
 * principal mapping is by name only; and there are <em>no deny rules and no rule precedence</em> — it is a pure
 * allow-list, so the classic allow/deny-ordering vulnerability class cannot exist.
 *
 * <p>Configuration errors (unknown referenced role, inheritance cycle, malformed pattern, misordered builder calls)
 * fail fast — at {@code allow(...)} or {@link #build()} time, never silently at authorization time. Instances built by
 * this class are immutable and safe for concurrent use; the builder itself is single-threaded.
 */
public final class PolicyBuilder {

    private final Map<String, RoleDef> roles = new LinkedHashMap<>();
    private final Map<String, Set<String>> principalRoles = new LinkedHashMap<>();

    private RoleDef currentRole;
    private String currentPrincipal;

    PolicyBuilder() {}

    /** Selects (creating if needed) the role that subsequent {@code allow}/{@code inherit} calls apply to. */
    public PolicyBuilder role(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("role name must be non-empty");
        }
        currentRole = roles.computeIfAbsent(name, RoleDef::new);
        currentPrincipal = null;
        return this;
    }

    /** Grants {@code action} on the MBeans matching {@code objectNamePattern} ({@code "*"} = any name). */
    public PolicyBuilder allow(JmxAction action, String objectNamePattern) {
        requireRole("allow");
        if (action == null) {
            throw new IllegalArgumentException("action");
        }
        if (objectNamePattern == null) {
            throw new IllegalArgumentException("objectNamePattern (use allow(action) for an untargeted grant)");
        }
        currentRole.grants.add(new Grant(action, toPattern(objectNamePattern)));
        return this;
    }

    /**
     * Grants {@code action} with no target constraint — the correct form for the untargeted {@code READ} forms
     * ({@code queryNames} / {@code getDomains}).
     */
    public PolicyBuilder allow(JmxAction action) {
        requireRole("allow");
        if (action == null) {
            throw new IllegalArgumentException("action");
        }
        currentRole.grants.add(new Grant(action, null));
        return this;
    }

    /** The current role additionally receives every grant of {@code roleName} (resolved transitively at build). */
    public PolicyBuilder inherit(String roleName) {
        requireRole("inherit");
        if (roleName == null || roleName.isEmpty()) {
            throw new IllegalArgumentException("inherited role name must be non-empty");
        }
        currentRole.inherits.add(roleName);
        return this;
    }

    /** Selects the principal (by name) that the subsequent {@link #grantedRoles(String...)} call applies to. */
    public PolicyBuilder principal(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("principal name must be non-empty");
        }
        currentPrincipal = name;
        currentRole = null;
        principalRoles.computeIfAbsent(name, k -> new HashSet<>());
        return this;
    }

    /** Grants the named roles to the current principal (RBAC union — repeatable, additive). */
    public PolicyBuilder grantedRoles(String... roleNames) {
        if (currentPrincipal == null) {
            throw new IllegalStateException("grantedRoles(...) called before principal(...)");
        }
        if (roleNames == null || roleNames.length == 0) {
            throw new IllegalArgumentException("grantedRoles requires at least one role");
        }
        Set<String> assigned = principalRoles.get(currentPrincipal);
        for (String r : roleNames) {
            if (r == null || r.isEmpty()) {
                throw new IllegalArgumentException("granted role name must be non-empty");
            }
            assigned.add(r);
        }
        return this;
    }

    /** Validates the configuration (referenced roles exist, no inheritance cycles) and returns the immutable policy. */
    public JmxmpAccessControl build() {
        // Every referenced role must be defined (a typo would otherwise silently over-restrict).
        for (RoleDef rd : roles.values()) {
            for (String inh : rd.inherits) {
                if (!roles.containsKey(inh)) {
                    throw new IllegalStateException("role '" + rd.name + "' inherits unknown role '" + inh + "'");
                }
            }
        }
        for (Map.Entry<String, Set<String>> e : principalRoles.entrySet()) {
            for (String r : e.getValue()) {
                if (!roles.containsKey(r)) {
                    throw new IllegalStateException(
                            "principal '" + e.getKey() + "' is granted unknown role '" + r + "'");
                }
            }
        }
        // Flatten inheritance (with cycle detection) into a per-role grant set.
        Map<String, List<Grant>> flattened = new HashMap<>();
        for (String roleName : roles.keySet()) {
            flattened.put(roleName, flatten(roleName, new ArrayDeque<>()));
        }
        Map<String, Set<String>> principalRolesCopy = new HashMap<>();
        principalRoles.forEach((p, rs) -> principalRolesCopy.put(p, Set.copyOf(rs)));
        return new RbacPolicy(Map.copyOf(flattened), Map.copyOf(principalRolesCopy));
    }

    private List<Grant> flatten(String roleName, Deque<String> path) {
        if (path.contains(roleName)) {
            throw new IllegalStateException("role inheritance cycle: " + String.join(" -> ", path) + " -> " + roleName);
        }
        path.push(roleName);
        List<Grant> out = new ArrayList<>(roles.get(roleName).grants);
        for (String inh : roles.get(roleName).inherits) {
            out.addAll(flatten(inh, path));
        }
        path.pop();
        return out;
    }

    private void requireRole(String op) {
        if (currentRole == null) {
            throw new IllegalStateException(op + "(...) called before role(...)");
        }
    }

    private static ObjectName toPattern(String pattern) {
        try {
            return new ObjectName("*".equals(pattern) ? "*:*" : pattern);
        } catch (MalformedObjectNameException e) {
            throw new IllegalArgumentException("malformed ObjectName pattern: '" + pattern + "'", e);
        }
    }

    private static final class RoleDef {
        final String name;
        final List<Grant> grants = new ArrayList<>();
        final Set<String> inherits = new HashSet<>();

        RoleDef(String name) {
            this.name = name;
        }
    }

    /** One allow-rule: an action, plus an optional {@code ObjectName} pattern (null = any/no target). */
    private record Grant(JmxAction action, ObjectName pattern) {
        boolean matches(JmxAccessRequest req) {
            if (req.action() != action) {
                return false;
            }
            if (pattern == null) {
                return true;
            }
            ObjectName target = req.target();
            if (target == null || target.isPattern()) {
                return false;
            }
            return pattern.apply(target);
        }
    }

    /** Immutable, concurrency-safe default-deny RBAC policy. Off the public API surface on purpose. */
    private record RbacPolicy(Map<String, List<Grant>> rolesFlattened, Map<String, Set<String>> principalRoles)
            implements JmxmpAccessControl {

        @Override
        public void checkAccess(Subject subject, JmxAccessRequest request) {
            if (subject == null || request == null) {
                throw new SecurityException("Access denied: no authenticated subject in scope.");
            }
            for (var principal : subject.getPrincipals()) {
                Set<String> granted = principalRoles.get(principal.getName());
                if (granted == null) {
                    continue;
                }
                for (String roleName : granted) {
                    for (Grant g : rolesFlattened.getOrDefault(roleName, List.of())) {
                        if (g.matches(request)) {
                            return; // allowed
                        }
                    }
                }
            }
            throw new SecurityException(
                    "Access denied: " + request.action() + (request.target() != null ? " on " + request.target() : ""));
        }
    }
}
