/*
 * Validation — public API compatibility check (OS-agnostic, no shell).
 *
 * Reimplements the former api-diff.sh in pure Java: regenerates
 * `javap -public` (via the system ToolProvider) for every FROZEN top-level
 * type under javax.management.remote.* from the built `common` jar and diffs
 * it against the captured v1.5.0 snapshot (a test resource).
 *
 * Frozen contract = the genuinely-public OpenDMK connector API. Allowed
 * deltas, normalized away here:
 *   - GenericConnector additionally implements java.io.Serializable
 *     (additive, intended serialization hardening, serialVersionUID pinned);
 *   - private inner classes ($1, $RequestHandler, …) and the
 *     Client/ServerIntermediary types moved into the engines — only
 *     top-level frozen types are compared;
 *   - javap member ordering is not a binary-compat property — members are
 *     sorted before diffing.
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.spi.ToolProvider;
import java.util.stream.Stream;
import org.testng.annotations.Test;

public class ApiSnapshotIT {

    private static final String SNAPSHOT_RESOURCE = "/api-snapshot-v1.5.0.txt";

    /** The frozen, FQN-preserved public OpenDMK connector API surface. */
    private static final String[] FROZEN = {
        "javax.management.remote.jmxmp.JMXMPConnector",
        "javax.management.remote.jmxmp.JMXMPConnectorServer",
        "javax.management.remote.generic.ConnectionClosedException",
        "javax.management.remote.generic.GenericConnector",
        "javax.management.remote.generic.GenericConnectorServer",
        "javax.management.remote.generic.MessageConnection",
        "javax.management.remote.generic.MessageConnectionServer",
        "javax.management.remote.generic.ObjectWrapping",
        "javax.management.remote.message.CloseMessage",
        "javax.management.remote.message.HandshakeBeginMessage",
        "javax.management.remote.message.HandshakeEndMessage",
        "javax.management.remote.message.HandshakeErrorMessage",
        "javax.management.remote.message.MBeanServerRequestMessage",
        "javax.management.remote.message.MBeanServerResponseMessage",
        "javax.management.remote.message.Message",
        "javax.management.remote.message.NotificationRequestMessage",
        "javax.management.remote.message.NotificationResponseMessage",
        "javax.management.remote.message.ProfileMessage",
        "javax.management.remote.message.SASLMessage",
        "javax.management.remote.message.TLSMessage",
        "javax.management.remote.message.VersionMessage",
    };

    @Test
    public void frozenPublicApiMatchesV150Snapshot() throws Exception {
        Path commonJar = TestPaths.jarOf("javax.management.remote.message.Message");
        Map<String, List<String>> baseline = parseSnapshot();
        ToolProvider javap = ToolProvider.findFirst("javap")
                .orElseThrow(() -> new IllegalStateException("javap ToolProvider unavailable (need a full JDK)"));

        StringBuilder report = new StringBuilder();
        for (String fqn : FROZEN) {
            List<String> old = baseline.get(fqn);
            if (old == null || old.isEmpty()) {
                report.append("ABSENT FROM BASELINE: ").append(fqn).append('\n');
                continue;
            }
            StringWriter out = new StringWriter();
            StringWriter err = new StringWriter();
            int rc = javap.run(new PrintWriter(out), new PrintWriter(err), "-public", "-cp", commonJar.toString(), fqn);
            if (rc != 0) {
                report.append("javap failed for ")
                        .append(fqn)
                        .append(" rc=")
                        .append(rc)
                        .append(" : ")
                        .append(err.toString().trim())
                        .append('\n');
                continue;
            }
            List<String> got = normalize(out.toString().lines().toList());
            List<String> want = normalize(old);
            if (!got.equals(want)) {
                report.append("DIFF: ").append(fqn).append('\n');
                for (String l : want) {
                    if (!got.contains(l)) {
                        report.append("  - ").append(l).append('\n');
                    }
                }
                for (String l : got) {
                    if (!want.contains(l)) {
                        report.append("  + ").append(l).append('\n');
                    }
                }
            }
        }
        assertTrue(
                report.isEmpty(), "Public API drift vs v1.5.0 across " + FROZEN.length + " frozen types:\n" + report);
    }

    /**
     * Normalize a javap block: drop the {@code Compiled from} / {@code //} noise, strip the documented
     * {@code java.io.Serializable} delta, collapse whitespace, drop blanks, sort (member order is not a contract).
     */
    private static List<String> normalize(List<String> raw) {
        TreeSet<String> sorted = new TreeSet<>();
        for (String line : raw) {
            if (line.startsWith("Compiled from") || line.startsWith("//")) {
                continue;
            }
            String s = line.replaceAll(",\\s*java\\.io\\.Serializable", "")
                    .replaceAll("java\\.io\\.Serializable\\s*,", "")
                    .replaceAll("\\s+", " ")
                    .trim();
            if (!s.isEmpty()) {
                sorted.add(s);
            }
        }
        return new ArrayList<>(sorted);
    }

    /** Parse the {@code === FQN ===}-delimited snapshot resource into per-type raw line blocks. */
    private static Map<String, List<String>> parseSnapshot() throws Exception {
        Map<String, List<String>> blocks = new LinkedHashMap<>();
        try (InputStream in = ApiSnapshotIT.class.getResourceAsStream(SNAPSHOT_RESOURCE)) {
            if (in == null) {
                fail("snapshot resource not found on test path: " + SNAPSHOT_RESOURCE);
            }
            List<String> all = new ArrayList<>();
            String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            try (Stream<String> lines = text.lines()) {
                lines.forEach(all::add);
            }
            String current = null;
            List<String> buf = null;
            for (String line : all) {
                if (line.startsWith("=== ") && line.endsWith(" ===")) {
                    current = line.substring(4, line.length() - 4).trim();
                    buf = new ArrayList<>();
                    blocks.put(current, buf);
                } else if (buf != null) {
                    buf.add(line);
                }
            }
        }
        return blocks;
    }
}
