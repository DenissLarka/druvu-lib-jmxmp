/*
 * JmxmpAccessControl.java
 *
 * New in the com.druvu fork (2.0) — not part of the original OpenDMK code.
 * The server-side fine-grained authorization SPI: the pluggable, code-only
 * replacement for the removed Security-Manager / MBeanPermission model and the
 * deleted 2007 file-properties access controller.
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

import javax.security.auth.Subject;

/**
 * Server-side, per-operation authorization SPI for inbound JMXMP connections — the typed, code-only successor to the
 * Security-Manager / {@code MBeanPermission} model JEP&nbsp;486 removed and to the deleted 2007 properties-file access
 * controller.
 *
 * <p><b>Where authorization sits.</b> Authentication is mandatory and independent: the server already requires
 * {@code TLS + SASL/PLAIN + JMXAuthenticator}, so there is always an authenticated {@link Subject}. Authorization
 * layers on top of that, per the env-{@code Map} value placed under {@link #ENV_KEY}:
 *
 * <table border="1">
 *   <caption>Default semantics</caption>
 *   <tr><th>{@code ENV_KEY} value</th><th>Behaviour</th></tr>
 *   <tr><td>absent</td><td>authenticated-but-unrestricted — every authenticated subject may do anything (the expected
 *       JMX default; <em>not</em> fail-open: identity is real and entry is gated by mandatory authentication)</td></tr>
 *   <tr><td>a {@code JmxmpAccessControl} instance</td><td>enforced per operation, <strong>strict default-deny</strong>
 *       (no grant ⇒ {@link SecurityException}, no fall-through)</td></tr>
 *   <tr><td>{@link #allowAll()}</td><td>explicit open — authentication-only, by deliberate code</td></tr>
 *   <tr><td>any non-{@code JmxmpAccessControl} value (e.g. a {@code String} from {@code -D}/props)</td>
 *       <td><strong>fail-closed</strong> {@code SecurityException} at server start — the code-only guarantee is
 *       enforced, not merely documented</td></tr>
 * </table>
 *
 * <p><b>Code-only by construction.</b> Like {@link ClientProfilePolicy}, the relaxed/open posture takes effect only
 * when an instance of this type is supplied in code. A {@code -D} system property, a properties file, or any
 * {@code String} under {@link #ENV_KEY} can never satisfy {@code instanceof JmxmpAccessControl}, so the open-server
 * opt-out cannot be flipped by ops tooling, configuration management, or the command line.
 *
 * <p><b>No legacy fail-open.</b> The old "null {@code Subject} ⇒ allow all" path is gone. With the Phase&nbsp;1
 * {@code Subject.current()} migration the authenticated subject is always reliably present, and a configured control
 * never falls through to allow — the JDK-25 authorization-bypass is structurally impossible here.
 */
public interface JmxmpAccessControl {

    /**
     * Authorizes a single intercepted {@code MBeanServer} operation.
     *
     * @param subject the authenticated subject in scope (from {@code Subject.current()}); never {@code null} on a
     *     properly authenticated request
     * @param request the operation being attempted; never {@code null}
     * @throws SecurityException if {@code subject} may not perform {@code request} — this is the JMX-contract exception
     *     callers already handle; the operation never reaches the real {@code MBeanServer}
     */
    void checkAccess(Subject subject, JmxAccessRequest request);

    /** Env-{@code Map} key; only a {@code JmxmpAccessControl} instance placed under this key is honoured. */
    String ENV_KEY = "com.druvu.jmxmp.server.accessControl";

    /**
     * The explicit, code-only "authenticated subjects may do anything" sentinel.
     *
     * <p>This is a typed singleton: a {@code String}/properties value under {@link #ENV_KEY} can never be
     * {@code instanceof JmxmpAccessControl}, so opening the server is only ever possible by writing Java against this
     * method — never by configuration. Identical guarantee to {@link ClientProfilePolicy#unrestricted()}.
     */
    static JmxmpAccessControl allowAll() {
        return AllowAll.INSTANCE;
    }

    /**
     * Entry point for the one built-in, programmatic, default-deny RBAC policy — roles (with {@code inherit}),
     * {@code ObjectName}-pattern targets, and principal-name → role grants. No file format. See {@link PolicyBuilder}.
     *
     * <pre>{@code
     * JmxmpAccessControl ac = JmxmpAccessControl.policy()
     *     .role("ro").allow(JmxAction.READ, "*")
     *     .role("ops").inherit("ro")
     *         .allow(JmxAction.INVOKE, "com.acme:type=Cache,*")
     *         .allow(JmxAction.WRITE, "com.acme:type=Cache,*")
     *     .principal("alice").grantedRoles("ops")
     *     .build();
     * }</pre>
     */
    static PolicyBuilder policy() {
        return new PolicyBuilder();
    }
}

/**
 * Package-private singleton backing {@link JmxmpAccessControl#allowAll()}. Kept off the public API surface on purpose —
 * only the typed factory method is exposed, so the open-server opt-out stays code-only and minimal.
 */
final class AllowAll implements JmxmpAccessControl {

    static final AllowAll INSTANCE = new AllowAll();

    private AllowAll() {}

    @Override
    public void checkAccess(Subject subject, JmxAccessRequest request) {
        // Explicit, deliberate no-op: authentication already happened; this is the
        // code-only opt-out from per-operation authorization.
    }
}
