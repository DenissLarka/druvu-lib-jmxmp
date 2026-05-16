// Final module descriptor. Client-side JMXMP engine + protocol provider,
// discovered by the GenericConnector facade and JMXConnectorFactory via
// ServiceLoader.
module com.druvu.jmxmp.client {
    requires transitive com.druvu.jmxmp.common;
    requires java.management;
    requires java.security.sasl;

    provides com.druvu.jmxmp.spi.GenericConnectorEngineProvider with
            com.druvu.jmxmp.client.generic.GenericConnectorEngineProviderImpl;
    provides javax.management.remote.JMXConnectorProvider with
            com.druvu.jmxmp.client.protocol.jmxmp.ClientProvider;
}
