// Server-side JMXMP engine + protocol provider, discovered by the
// GenericConnectorServer facade and JMXConnectorServerFactory via ServiceLoader;
// the server's configuration API (com.druvu.jmxmp.server) is exported, the engine
// is not. Loads the deployer-supplied JMXAuthenticator via ServiceLoader (SASL/PLAIN
// credential validation). The access module is transitive: the configuration API
// takes a JmxAccessControl.
module com.druvu.jmxmp.server {
    requires transitive com.druvu.jmxmp.common;
    requires transitive com.druvu.jmxmp.access;
    requires java.management;

    exports com.druvu.jmxmp.server;

    uses javax.management.remote.JMXAuthenticator;

    provides com.druvu.jmxmp.spi.GenericConnectorServerEngineProvider with
            com.druvu.jmxmp.server.generic.GenericConnectorServerEngineProviderImpl;
    provides javax.management.remote.JMXConnectorServerProvider with
            com.druvu.jmxmp.server.protocol.jmxmp.ServerProvider;
}
