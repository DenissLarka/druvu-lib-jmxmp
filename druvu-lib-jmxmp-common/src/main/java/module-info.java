// Public OpenDMK API (FQN-preserved: javax.management.remote.{jmxmp,message,generic}),
// the fork's shared configuration (com.druvu.jmxmp) and the SPI seam are exported to
// everyone; the protocol internals (internal, util) only to the client and server
// modules. Engine SPIs are discovered from the client/server modules; JMXAuthenticator
// from the consumer module (GenericConnectorServer mandatory-security gate).
module com.druvu.jmxmp.common {
    requires java.management;

    exports javax.management.remote.jmxmp;
    exports javax.management.remote.message;
    exports javax.management.remote.generic;
    exports com.druvu.jmxmp;
    exports com.druvu.jmxmp.spi;
    exports com.druvu.jmxmp.internal to
            com.druvu.jmxmp.client,
            com.druvu.jmxmp.server;
    exports com.druvu.jmxmp.util to
            com.druvu.jmxmp.client,
            com.druvu.jmxmp.server;

    uses com.druvu.jmxmp.spi.GenericConnectorEngineProvider;
    uses com.druvu.jmxmp.spi.GenericConnectorServerEngineProvider;
    uses javax.management.remote.JMXAuthenticator;
}
