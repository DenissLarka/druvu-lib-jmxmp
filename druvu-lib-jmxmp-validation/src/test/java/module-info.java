/*
 * Validation TEST module descriptor.
 *
 * Forces the matrix to resolve and run on the JPMS module path. The explicit
 * client + server requires is the split-package-freedom assertion: if any
 * package were shared across the client/server/common seam, the module
 * graph would fail to resolve here at test launch.
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
open module com.druvu.jmxmp.validation {
    requires com.druvu.jmxmp.client;
    requires com.druvu.jmxmp.server;
    requires java.management;
    requires java.security.sasl;
    requires org.testng;

    // The matrix asserts provider discovery via ServiceLoader
    // directly, so this consumer module must declare the `uses`.
    uses com.druvu.jmxmp.spi.GenericConnectorEngineProvider;
    uses com.druvu.jmxmp.spi.GenericConnectorServerEngineProvider;
    uses javax.management.remote.JMXConnectorProvider;
    uses javax.management.remote.JMXConnectorServerProvider;
}
