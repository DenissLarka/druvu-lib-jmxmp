/*
 * Validation — modular deployment-shape resolution (OS-agnostic, no shell).
 *
 * Reimplements the former module-graphs.sh in pure Java. Proves the
 * three-module graph degrades correctly when only part of it is present:
 *
 *   client-only  : {common, client} resolves WITHOUT server
 *   server-only  : {common, server} resolves WITHOUT client
 *   common-only  : a consumer seeing only `common` gets the documented
 *                  "add com.druvu.jmxmp.client to the module path"
 *                  IllegalStateException — no silent failure
 *   consumer     : an unchanged frozen-public-API consumer still compiles
 *                  against just the new `common` jar
 *
 * Resolution and the consumer recompile run in-process (java.lang.module +
 * the javac ToolProvider). The engine-missing case needs a JVM that genuinely
 * cannot see client/server (this test JVM's boot layer already has them), so
 * it launches a probe with the JDK's own `java` via ProcessBuilder — no shell,
 * cross-platform (java.home + .exe on Windows).
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.lang.module.Configuration;
import java.lang.module.ModuleFinder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.spi.ToolProvider;
import java.util.stream.Stream;
import org.testng.annotations.Test;

public class DeploymentShapesIT {

    @Test
    public void clientResolvesWithoutServer() throws Exception {
        Path common = TestPaths.jarOf(TestPaths.COMMON_CLASS);
        Path client = TestPaths.jarOf(TestPaths.CLIENT_CLASS);
        Configuration cf = Configuration.resolve(
                ModuleFinder.of(common, client),
                List.of(Configuration.empty()),
                ModuleFinder.ofSystem(),
                List.of("com.druvu.jmxmp.client"));
        assertTrue(cf.findModule("com.druvu.jmxmp.client").isPresent(), "client must resolve");
        assertTrue(cf.findModule("com.druvu.jmxmp.common").isPresent(), "common pulled in transitively");
        assertTrue(
                cf.findModule("com.druvu.jmxmp.server").isEmpty(), "server must NOT be required by the client closure");
    }

    @Test
    public void serverResolvesWithoutClient() throws Exception {
        Path common = TestPaths.jarOf(TestPaths.COMMON_CLASS);
        Path server = TestPaths.jarOf(TestPaths.SERVER_CLASS);
        Configuration cf = Configuration.resolve(
                ModuleFinder.of(common, server),
                List.of(Configuration.empty()),
                ModuleFinder.ofSystem(),
                List.of("com.druvu.jmxmp.server"));
        assertTrue(cf.findModule("com.druvu.jmxmp.server").isPresent(), "server must resolve");
        assertTrue(cf.findModule("com.druvu.jmxmp.common").isPresent(), "common pulled in transitively");
        assertTrue(
                cf.findModule("com.druvu.jmxmp.client").isEmpty(), "client must NOT be required by the server closure");
    }

    @Test
    public void commonOnlyGivesHelpfulEngineMissingError() throws Exception {
        Path common = TestPaths.jarOf(TestPaths.COMMON_CLASS);
        Path work = Files.createTempDirectory("jmxmp-probe");
        try {
            Path src = Files.createDirectories(work.resolve("src"));
            Path out = Files.createDirectories(work.resolve("out"));
            Files.writeString(src.resolve("module-info.java"), "module probe { requires com.druvu.jmxmp.common; }\n");
            Path pkg = Files.createDirectories(src.resolve("probe"));
            Files.writeString(pkg.resolve("Probe.java"), """
                    package probe;
                    import java.util.HashMap;
                    import java.util.Map;
                    import javax.management.remote.generic.GenericConnector;
                    public final class Probe {
                        public static void main(String[] a) {
                            Map env = new HashMap();
                            env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
                            try {
                                new GenericConnector(env).connect(env);
                                System.out.println("PROBE-UNEXPECTED-OK");
                            } catch (IllegalStateException e) {
                                System.out.println("PROBE-ISE:" + e.getMessage());
                            } catch (Throwable t) {
                                System.out.println("PROBE-OTHER:" + t.getClass().getName() + ":" + t.getMessage());
                            }
                        }
                    }
                    """);

            ToolProvider javac = ToolProvider.findFirst("javac").orElseThrow();
            int rc = javac.run(
                    new java.io.PrintWriter(System.out),
                    new java.io.PrintWriter(System.err),
                    "--module-path",
                    common.toString(),
                    "-d",
                    out.toString(),
                    src.resolve("module-info.java").toString(),
                    pkg.resolve("Probe.java").toString());
            assertEquals(rc, 0, "probe module must compile against common only");

            String mp = common.toString() + java.io.File.pathSeparator + out;
            Process p = new ProcessBuilder(javaExe(), "--module-path", mp, "-m", "probe/probe.Probe")
                    .redirectErrorStream(true)
                    .start();
            String stdout = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            p.waitFor();
            assertTrue(
                    stdout.contains("PROBE-ISE:") && stdout.contains("add com.druvu.jmxmp.client to the module path"),
                    "expected engine-missing IllegalStateException, got: " + stdout.trim());
        } finally {
            deleteTree(work);
        }
    }

    @Test
    public void unchangedFrozenApiConsumerStillCompiles() throws Exception {
        Path common = TestPaths.jarOf(TestPaths.COMMON_CLASS);
        Path work = Files.createTempDirectory("jmxmp-consumer");
        try {
            Path src = work.resolve("Consumer.java");
            Path out = Files.createDirectories(work.resolve("out"));
            Files.writeString(src, """
                    import java.util.HashMap;
                    import java.util.Map;
                    import javax.management.remote.JMXConnector;
                    import javax.management.remote.JMXConnectorFactory;
                    import javax.management.remote.JMXServiceURL;
                    import javax.management.remote.jmxmp.JMXMPConnector;
                    public final class Consumer {
                        public static JMXConnector mk(JMXServiceURL u, Map<String, ?> env) throws Exception {
                            return JMXConnectorFactory.newJMXConnector(u, env);
                        }
                        public static JMXMPConnector direct(JMXServiceURL u) throws Exception {
                            return new JMXMPConnector(u, new HashMap<String, Object>());
                        }
                    }
                    """);
            ToolProvider javac = ToolProvider.findFirst("javac").orElseThrow();
            int rc = javac.run(
                    new java.io.PrintWriter(System.out),
                    new java.io.PrintWriter(System.err),
                    "-cp",
                    common.toString(),
                    "-d",
                    out.toString(),
                    src.toString());
            assertEquals(rc, 0, "frozen-public-API consumer must still compile against the new common jar");
        } finally {
            deleteTree(work);
        }
    }

    private static String javaExe() {
        boolean win = System.getProperty("os.name", "").toLowerCase().contains("win");
        return Path.of(System.getProperty("java.home"), "bin", win ? "java.exe" : "java")
                .toString();
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> s = Files.walk(root)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best-effort temp cleanup
                }
            });
        }
    }
}
