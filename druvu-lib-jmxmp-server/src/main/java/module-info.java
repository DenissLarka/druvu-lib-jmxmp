// Final module descriptor. Server-side JMXMP engine + protocol provider,
// discovered by the GenericConnectorServer facade and
// JMXConnectorServerFactory via ServiceLoader. Loads the deployer-supplied
// JMXAuthenticator via ServiceLoader (SASL/PLAIN credential validation).
module com.druvu.jmxmp.server {
    requires transitive com.druvu.jmxmp.common;
    requires java.management;

    uses javax.management.remote.JMXAuthenticator;

    provides com.druvu.jmxmp.spi.GenericConnectorServerEngineProvider with
            com.druvu.jmxmp.server.generic.GenericConnectorServerEngineProviderImpl;
    provides javax.management.remote.JMXConnectorServerProvider with
            com.druvu.jmxmp.server.protocol.jmxmp.ServerProvider;
}
