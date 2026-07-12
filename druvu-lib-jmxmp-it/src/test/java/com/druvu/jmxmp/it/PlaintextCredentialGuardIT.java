package com.druvu.jmxmp.it;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.expectThrows;

import com.druvu.jmxmp.shared.ClientProfilePolicy;
import com.druvu.jmxmp.shared.SelectProfiles;
import java.util.HashMap;
import java.util.Map;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import org.testng.annotations.Test;

/**
 * Guards the invariant that the client enforces its transport policy <b>before</b> any credential-bearing profile runs:
 * a policy violation on the negotiated profile set must abort the handshake before SASL/PLAIN transmits the password.
 *
 * <p>Regression target: a custom {@link SelectProfiles} selector (as JConsoleBooster installs) that downgrades to the
 * server's offer can drop TLS; if the profile policy is only checked <em>after</em> the profile loop, the password has
 * already crossed a plaintext wire. The authenticator's call count is the wire-level probe — it is invoked only if the
 * SASL/PLAIN exchange actually reached the server.
 */
public class PlaintextCredentialGuardIT {

    @Test
    public void policyRejectsDowngradeBeforeCredentialsReachTheServer() throws Exception {
        MBeanServer mbs = MBeanServerFactory.newMBeanServer();
        TestAuthenticator auth = new TestAuthenticator(Map.of("admin", "s3cr3t"));

        // A normal secured server (jmxmp refuses to run plaintext at all — plaintext servers are unsupported by
        // design, so a downgrade can only come from a hostile/impersonating endpoint; here the server is honest and
        // the DOWNGRADE is injected on the client via a custom selector, exactly as a TLS-strip would surface).
        Map<String, Object> senv = new HashMap<>();
        senv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        senv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
        senv.put(JMXConnectorServer.AUTHENTICATOR, auth);

        JMXServiceURL url = new JMXServiceURL("jmxmp", "localhost", 0);
        JMXConnectorServer server = JMXConnectorServerFactory.newJMXConnectorServer(url, senv, mbs);
        server.start();
        try {
            Map<String, Object> cenv = new HashMap<>();
            // Passes the construction-time spec check, then the selector downgrades the chosen set to plaintext.
            cenv.put("jmx.remote.profiles", "TLS SASL/PLAIN");
            cenv.put("jmx.remote.tls.socket.factory", TlsTestSupport.socketFactory());
            SelectProfiles downgrade = (env, serverProfiles) -> env.put("jmx.remote.profiles", "SASL/PLAIN");
            cenv.put("com.sun.jmx.remote.profile.selector", downgrade);
            cenv.put(ClientProfilePolicy.ENV_KEY, ClientProfilePolicy.mandatoryTlsSasl());
            cenv.put(JMXConnector.CREDENTIALS, new String[] {"admin", "s3cr3t"});

            JMXServiceURL address = server.getAddress();
            expectThrows(Exception.class, () -> JMXConnectorFactory.connect(address, cenv));

            // The pre-loop policy check aborts before the SASL/PLAIN profile runs, so the credential never leaves the
            // client and the server's authenticator is never reached.
            assertEquals(
                    auth.calls.get(),
                    0,
                    "policy must reject the downgrade BEFORE SASL runs — the authenticator must never be reached");
        } finally {
            server.stop();
        }
    }
}
