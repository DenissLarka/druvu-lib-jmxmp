/*
 * Validation — TLS material. Dependency-free self-signed PKCS12
 * keystore via the JDK's keytool, one SSLContext for both loopback ends.
 * Mirrors it/TlsTestSupport (cannot be reused across modules/test scopes).
 *
 * Dual-licensed GPLv2+CPE or CDDL-1.0 — see the LICENSE file at the repo root.
 */
package com.druvu.jmxmp.validation;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

final class TlsSupport {

    static final String STORE_PASSWORD = "changeit";
    private static final String ALIAS = "jmxmp";
    private static volatile SSLSocketFactory factory;

    private TlsSupport() {}

    static synchronized SSLSocketFactory socketFactory() throws Exception {
        if (factory != null) {
            return factory;
        }
        File store = new File("target/validation-keystore.p12");
        if (!store.exists()) {
            generateKeystore(store);
        }
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = new FileInputStream(store)) {
            ks.load(in, STORE_PASSWORD.toCharArray());
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, STORE_PASSWORD.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        factory = ctx.getSocketFactory();
        return factory;
    }

    private static void generateKeystore(File store) throws Exception {
        store.getParentFile().mkdirs();
        String keytool = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
        Process p = new ProcessBuilder(
                        keytool,
                        "-genkeypair",
                        "-alias",
                        ALIAS,
                        "-keyalg",
                        "RSA",
                        "-keysize",
                        "2048",
                        "-dname",
                        "CN=localhost",
                        "-validity",
                        "1",
                        "-storetype",
                        "PKCS12",
                        "-keystore",
                        store.getAbsolutePath(),
                        "-storepass",
                        STORE_PASSWORD,
                        "-keypass",
                        STORE_PASSWORD)
                .redirectErrorStream(true)
                .start();
        try (InputStream ignored = p.getInputStream()) {
            ignored.readAllBytes();
        }
        int code = p.waitFor();
        if (code != 0 || !store.exists()) {
            throw new IllegalStateException("keytool failed to create validation keystore (exit " + code + ")");
        }
    }
}
