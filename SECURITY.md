# Security Policy — druvu-lib-jmxmp

This is a network-facing library that performs authentication, TLS transport,
and — by the nature of the JMXMP protocol — **Java object deserialization of
data received from a peer**. Read this document before deploying it in any
environment where the peer is not fully trusted.

It is a fork of the 2007-era OpenDMK `jmx-optional` reference implementation.
Legacy code paths have been reviewed and substantially reduced (see
[What this fork removed](#what-this-fork-removed)), but the codebase has **not
undergone a formal third-party security audit**.

## Support model — read this first

This is maintained by a **single maintainer on a best-effort basis**. There is
**no SLA and no guaranteed response time.** Concretely:

- Security fixes are produced for the **latest released version only**. There
  is no back-porting to older versions.
- "Maintained" here means: reported vulnerabilities will be triaged and, where
  valid and practical, fixed in a reasonable timeframe — *not* that a fix is
  guaranteed within any fixed window.
- The project may be declared end-of-life with a notice in this file and the
  README. If that happens, treat the last release as frozen and unmaintained.

If your deployment needs a contractual security SLA, do not rely on this
library — vendor it, audit it yourself, and own the maintenance.

## Supported versions

| Version                   | Supported                            |
|---------------------------|--------------------------------------|
| latest release            | ✅ best-effort security fixes         |
| any earlier version       | ❌ not supported                      |
| pre-release / `-SNAPSHOT` | ❌ not supported — not for production |

The library is currently **pre-release** (not published to Maven Central). No
version is under a support commitment until a `2.0.0` release is tagged.

## Reporting a vulnerability

**Do not open a public issue or pull request for a suspected vulnerability.**

Report privately via **GitHub's "Report a vulnerability" / private security
advisory** on this repository
(`https://github.com/DenissLarka/druvu-lib-jmxmp` → Security → Advisories).
This routes triage without public exposure and requires no monitored inbox.

Please include: affected version/commit, a description of the issue, a
reproduction or PoC if available, and the impact you believe it has.

Expectations, stated honestly:

- Acknowledgement: best-effort, typically within a few days — not guaranteed.
- Coordinated disclosure: please allow a reasonable period to investigate and
  fix before any public disclosure. There is no fixed embargo; it will be
  agreed case by case.
- Credit: reporters are credited in the advisory and release notes unless they
  ask not to be.

## What this fork removed (deliberate attack-surface reduction)

The following were cut **on purpose** relative to upstream OpenDMK. These are
not configurable — there is no escape hatch.

- **No plaintext transport.** The only accepted profile set is exactly
  `TLS SASL/PLAIN`. A connection without TLS is refused at construction.
  Passive sniffing and trivial MITM of cleartext JMX are eliminated.
- **No unauthenticated access path.** A `JMXAuthenticator` is mandatory on the
  server; it cannot be constructed without one. The opt-out
  (`AllowAnyAuthenticator`) refuses to construct unless the deployer sets an
  explicit acknowledgement token
  (`com.druvu.jmxmp.security.acknowledge.allow.any=YES_I_ACCEPT_NO_AUTHENTICATION`).
  There is no silent "no auth" default.
- **No security downgrade negotiation.** Exactly `{ TLS, SASL/PLAIN }` is
  accepted. Every other SASL mechanism — CRAM-MD5, DIGEST-MD5, GSSAPI,
  EXTERNAL, OAUTHBEARER — is rejected **at construction**, not after a
  handshake. The "negotiate the peer down to a weak mechanism" class is gone.
- **RMI code path removed.** All `java.rmi` usage (the RMI connector /
  exporter / `UnicastRemoteObject` paths inherited from OpenDMK) was deleted.
  JMXMP is socket-only; there is no RMI registry or RMI export surface.
- **Pre-Java-21 reflection / compatibility shims removed.** Old reflective
  fallbacks (a historical source of surprising behaviour) are gone. Baseline
  is Java 21.
- **JPMS strong encapsulation.** Internal packages are not exported; only the
  public `javax.management.remote.*` API and the SPI are reachable. A
  client-only deployment does not carry the server accept loop, and vice
  versa.

## What remains is — the residual attack surface

Be clear-eyed about this. The mitigations above reduce surface; they do not
make the library safe to expose to untrusted peers.

### Java deserialization (the principal residual risk)

JMXMP transfers **serialized Java objects** in both directions — MBean
operation parameters and return values, attribute values, and notifications
all cross the wire via Java serialization. This library performs
`ObjectInputStream`-style deserialization of those payloads. This is inherent
to the JMXMP protocol and **cannot be removed without breaking the protocol**.

What bounds it in this fork:

- **A built-in, default-deny serialization allow-list is installed on every
  wire deserialization** — both the JMXMP protocol-message stream (from the
  very first handshake message, *pre-authentication*) and the MBean
  payload stream. It allows only the JMX object model, the JMXMP message
  types, authentication value types, and safe JDK value types
  (`java.lang/util/math/time`); **everything else is rejected**. The
  classic deserialization gadget sinks (commons-collections,
  `com.sun.rowset.JdbcRowSetImpl`, Xalan `TemplatesImpl`, `sun.*`,
  `javassist`, `bsh`, …) fall outside the allow-list and are refused. It
  also rejects oversized graphs (depth/refs/array-length caps) to blunt
  decompression-style DoS. This filter is **merged with**, never weakens,
  any process-wide `jdk.serialFilter` you set — a reject from either wins.
- Deserialization-heavy MBean traffic only flows **after** a successful
  TLS handshake **and** a successful `JMXAuthenticator` check. An anonymous
  off-path attacker cannot reach the payload stream.

What it does **not** protect against:

- A **malicious or compromised peer that holds valid credentials** can still
  send payloads built **only from allow-listed types** (the JMX model and
  JDK value types *must* be permitted for the protocol to function). The
  allow-list removes the well-known RCE gadget chains; it does not make
  deserialization of attacker-influenced data risk-free. Authentication and
  the allow-list both raise the bar; neither closes the surface entirely.
- The allow-list cannot know your application's own MBean parameter/return
  classes. Until you add them (below) those operations fail closed — which
  is the safe direction, but you **must** configure it for real MBeans.

### Deployer-owned surface

- **TLS configuration is yours, with a hardened default.** The library
  consumes an `SSLContext` / `SSLSocketFactory` that you supply. As of 2.0.0
  it defaults the enabled protocols to **TLS 1.3 only** on both the client and
  the server when `jmx.remote.tls.enabled.protocols` is unset; setting that
  env key overrides the default verbatim (the only way to re-enable TLS 1.2 or
  older). Certificate validation and peer authentication still come from the
  `SSLContext`/factory you supply and remain configuration failures the
  library cannot prevent.
- **The `JMXAuthenticator` is yours.** Its strength is entirely up to your
  implementation. `AllowAnyAuthenticator` authenticates nobody — it exists for
  deliberately-open deployments and is gated behind an explicit acknowledgement
  for exactly that reason.

## Hardening checklist for deployers

1. **Allow-list your MBean types — the built-in filter fails closed without
   them.** The library already installs a default-deny allow-list covering
   the JMX model and safe JDK types. For an MBean that exchanges application
   classes, add their package prefixes (`;`-separated, trailing prefix matches
   subpackages):

   ```
   -Dcom.druvu.jmxmp.serial.allow=com.acme.metrics.;com.acme.dto.
   ```

   Keep these prefixes as narrow as possible. For defense in depth you may
   *additionally* set a stricter process-wide `-Djdk.serialFilter=...` /
   `ObjectInputFilter.Config.setSerialFilter(...)`; it is composed with the
   built-in filter and a reject from either wins (it can only tighten, never
   loosen). Do **not** widen `com.druvu.jmxmp.serial.allow` to broad prefixes
   (`com.`, `org.`, `*`) — that re-opens the gadget surface the default-deny
   list exists to close.
2. **Use strong TLS.** The library already defaults to **TLS 1.3 only**; do
   not weaken it by setting `jmx.remote.tls.enabled.protocols` to include
   TLS 1.2 or older unless a legacy peer forces it (and then pin exactly the
   versions you need on both ends). Still your responsibility: full
   certificate validation and mutual TLS where the threat model warrants it.
   Do not pass a trust-all `SSLContext`.
3. **Supply a real `JMXAuthenticator`.** Do not ship `AllowAnyAuthenticator`
   to production. Consider the bearer-token-as-password pattern (treat the
   password slot as a short-lived OAuth/JWT or HMAC ticket — see the README)
   so a leaked credential is not a reusable secret.
4. **Constrain the network.** Bind to a specific interface or a trusted
   network segment; do not expose the JMXMP port to untrusted networks even
   with auth enabled.
5. **Least privilege.** Run the JVM with the minimum privileges and a security
   posture appropriate to "this process deserializes peer-supplied data".
6. **Stay on the latest version.** Only the latest release receives fixes.

## Provenance

Derived from OpenDMK `jmx-optional` (Sun Microsystems, 2007). Dual-licensed
GPL v2 with Classpath exception, or CDDL v1.0. Inherited code has been reduced
and modularized but not formally audited; treat its security properties as
"hardened fork", not "verified".
