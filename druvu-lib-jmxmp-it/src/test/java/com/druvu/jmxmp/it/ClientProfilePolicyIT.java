package com.druvu.jmxmp.it;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertThrows;
import static org.testng.Assert.fail;

import com.druvu.jmxmp.shared.CheckProfiles;
import com.druvu.jmxmp.shared.ClientProfilePolicy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.jmxmp.JMXMPConnector;
import org.testng.annotations.Test;

/**
 * Covers the 2.0 client-side typed escape hatch: secure by default, relaxable only via a {@link ClientProfilePolicy}
 * instance in the env (never via a string / system property). The server side is unaffected and is exercised by
 * {@link SecurityPolicyIT}.
 */
public class ClientProfilePolicyIT {

    private JMXServiceURL url() throws Exception {
        return new JMXServiceURL("jmxmp", "localhost", 0);
    }

    private Map<String, Object> env(Object... kv) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    // --- secure default (no policy, or explicit mandatory) is unchanged --------------------------------------------

    @Test
    public void noPolicyKeepsMandatoryDefault() throws Exception {
        // no jmx.remote.profiles + no policy → IllegalArgumentException, exactly as before the escape hatch existed
        try {
            new JMXMPConnector(url(), new HashMap<>());
            fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
        // wrong set + no policy → SecurityException
        assertThrows(SecurityException.class, () -> CheckProfiles.enforceClientSpec("TLS", env()));
        // explicit mandatory behaves identically
        assertThrows(
                SecurityException.class,
                () -> CheckProfiles.enforceClientSpec(
                        "TLS", env(ClientProfilePolicy.ENV_KEY, ClientProfilePolicy.mandatoryTlsSasl())));
        CheckProfiles.enforceClientSpec("TLS SASL/PLAIN", env()); // the good set still passes
    }

    // --- unrestricted() : anything, including none / plaintext ----------------------------------------------------

    @Test
    public void unrestrictedAllowsNoProfilesAndArbitrarySets() throws Exception {
        Map<String, Object> e = env(ClientProfilePolicy.ENV_KEY, ClientProfilePolicy.unrestricted());
        // constructs with no jmx.remote.profiles at all (plaintext client)
        new JMXMPConnector(url(), e);
        // direct policy checks: null / empty / arbitrary all pass
        CheckProfiles.enforceClientSpec(null, e);
        CheckProfiles.enforceClientSpec("TLS", e);
        CheckProfiles.enforceClient(List.of("TLS", "SASL/CRAM-MD5"), e);
        CheckProfiles.enforceClient(List.of(), e);
    }

    // --- require(...) : exactly the enumerated set ----------------------------------------------------------------

    @Test
    public void requirePinsExactSet() {
        Map<String, Object> tlsOnly = env(ClientProfilePolicy.ENV_KEY, ClientProfilePolicy.require("TLS"));
        CheckProfiles.enforceClientSpec("TLS", tlsOnly); // matches → ok
        CheckProfiles.enforceClient(List.of("tls"), tlsOnly); // case-insensitive → ok
        assertThrows(
                SecurityException.class,
                () -> CheckProfiles.enforceClient(List.of("TLS", "SASL/PLAIN"), tlsOnly)); // superset → reject
        assertThrows(
                IllegalArgumentException.class,
                () -> CheckProfiles.enforceClientSpec(null, tlsOnly)); // policy set but spec missing

        Map<String, Object> custom =
                env(ClientProfilePolicy.ENV_KEY, ClientProfilePolicy.require("TLS", "SASL/DIGEST-MD5"));
        CheckProfiles.enforceClient(List.of("SASL/DIGEST-MD5", "TLS"), custom); // order-independent → ok
    }

    @Test
    public void requireRejectsEmptyConstruction() {
        assertThrows(IllegalArgumentException.class, ClientProfilePolicy::require);
        assertThrows(IllegalArgumentException.class, () -> ClientProfilePolicy.require("TLS", " "));
    }

    // --- the code-only property: a String under the key is rejected, never honoured/ignored -----------------------

    @Test
    public void stringUnderKeyIsRejectedNotHonoured() throws Exception {
        // someone tries to relax via a string (e.g. injected from a -D property): must fail closed with a diagnostic,
        // never silently relax and never silently fall back
        Map<String, Object> spoof = env(ClientProfilePolicy.ENV_KEY, "unrestricted");
        try {
            new JMXMPConnector(url(), spoof);
            fail("expected SecurityException — a String must not relax the client policy");
        } catch (SecurityException expected) {
            assertEquals(expected.getMessage().contains(ClientProfilePolicy.ENV_KEY), true, expected.getMessage());
        }
        assertThrows(SecurityException.class, () -> CheckProfiles.enforceClient(List.of("TLS"), spoof));
    }
}
