/*
 * Validation — locate the built reactor jars for the OS-agnostic checks.
 *
 * Primary: the code source of an already-loaded class from the target module
 * (works on the module path). Fallback: scan the sibling target/ directory,
 * for the case where the code source is unavailable.
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

final class TestPaths {

    private TestPaths() {}

    /** A class FQN from each reactor module, used to locate that module's jar via its code source. */
    static final String COMMON_CLASS = "javax.management.remote.message.Message";

    static final String CLIENT_CLASS = "com.druvu.jmxmp.client.generic.GenericConnectorEngineImpl";
    static final String SERVER_CLASS = "com.druvu.jmxmp.server.generic.GenericConnectorServerEngineImpl";

    /** Resolve the jar that supplies {@code className}. */
    static Path jarOf(String className) throws Exception {
        Class<?> c = Class.forName(className);
        var cs = c.getProtectionDomain().getCodeSource();
        if (cs != null && cs.getLocation() != null) {
            Path p = Path.of(cs.getLocation().toURI());
            if (Files.isRegularFile(p)) {
                return p;
            }
        }
        return scanSiblingTarget(moduleArtifact(className));
    }

    private static String moduleArtifact(String className) {
        if (className.equals(CLIENT_CLASS)) {
            return "druvu-lib-jmxmp-client";
        }
        if (className.equals(SERVER_CLASS)) {
            return "druvu-lib-jmxmp-server";
        }
        return "druvu-lib-jmxmp-common";
    }

    /**
     * Fallback: from the validation module's working directory, find {@code ../<artifact>/target/<artifact>-*.jar}
     * (excluding sources/javadoc/test classifiers).
     */
    private static Path scanSiblingTarget(String artifact) throws Exception {
        Path repoRoot = Path.of("").toAbsolutePath();
        if (repoRoot.getFileName().toString().equals("druvu-lib-jmxmp-validation")) {
            repoRoot = repoRoot.getParent();
        }
        Path targetDir = repoRoot.resolve(artifact).resolve("target");
        try (Stream<Path> s = Files.list(targetDir)) {
            List<Path> hits = s.filter(p -> {
                        String n = p.getFileName().toString();
                        return n.startsWith(artifact + "-")
                                && n.endsWith(".jar")
                                && !n.contains("-sources")
                                && !n.contains("-javadoc")
                                && !n.contains("-tests");
                    })
                    .toList();
            if (hits.isEmpty()) {
                throw new IllegalStateException("no built jar for " + artifact + " in " + targetDir);
            }
            return hits.get(0);
        }
    }
}
