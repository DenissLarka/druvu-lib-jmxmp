// Final module descriptor. Public OpenDMK API (FQN-preserved:
// javax.management.remote.{jmxmp,message,generic}) + the renamed shared/util
// internals + the SPI seam + facades. Engine SPIs are discovered from the
// client/server modules; JMXAuthenticator from the consumer module
// (GenericConnectorServer mandatory-security gate).
module com.druvu.jmxmp.common {
    requires java.management;
    requires java.security.sasl;
    requires java.logging;

    exports javax.management.remote.jmxmp;
    exports javax.management.remote.message;
    exports javax.management.remote.generic;
    exports com.druvu.jmxmp.util;
    exports com.druvu.jmxmp.shared;
    exports com.druvu.jmxmp.spi;

    uses com.druvu.jmxmp.spi.GenericConnectorEngineProvider;
    uses com.druvu.jmxmp.spi.GenericConnectorServerEngineProvider;
    uses javax.management.remote.JMXAuthenticator;
}
