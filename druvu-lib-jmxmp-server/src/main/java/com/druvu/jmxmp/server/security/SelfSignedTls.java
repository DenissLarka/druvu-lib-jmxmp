package com.druvu.jmxmp.server.security;

import com.druvu.jmxmp.util.ClassLogger;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * Generates an ephemeral, self-signed TLS identity for the server when the deployer configures no
 * {@code jmx.remote.tls.socket.factory}. This makes the mandatory TLS profile usable with zero configuration: the
 * listener is encrypted out of the box (opportunistic, STARTTLS-style) instead of refusing to start or — as classic
 * plaintext JMXMP does — exposing everything in clear.
 *
 * <p><b>What it does and does not give you.</b> The certificate is self-signed and regenerated on every JVM start, so a
 * client has nothing stable to pin: this defeats <em>passive</em> interception but NOT an active man-in-the-middle
 * (which could present its own self-signed certificate and, because SASL/PLAIN carries credentials, capture them). For
 * real server-identity / MITM protection, supply your own {@code jmx.remote.tls.socket.factory} built from a trusted
 * keystore. The default is a pragmatic <em>encrypted-by-default, authenticated-by-choice</em> posture — never a
 * substitute for a real certificate.
 *
 * <p>The key material is produced with the JDK's own {@code keytool} (no third-party dependency). That tool must exist
 * in the runtime; in a stripped {@code jlink}/native image it may be absent, in which case configure
 * {@code jmx.remote.tls.socket.factory} explicitly.
 */
final class SelfSignedTls {

    private static final ClassLogger LOG = new ClassLogger("javax.management.remote.misc", "SelfSignedTls");
    private static final String STORE_PASSWORD = "changeit";
    private static final String ALIAS = "druvu-jmxmp-ephemeral";

    private static volatile SSLSocketFactory factory;

    private SelfSignedTls() {}

    /** The ephemeral self-signed server {@link SSLSocketFactory}, generated once per JVM and cached. */
    static SSLSocketFactory socketFactory() throws IOException {
        SSLSocketFactory f = factory;
        if (f != null) {
            return f;
        }
        synchronized (SelfSignedTls.class) {
            if (factory == null) {
                factory = generate();
            }
            return factory;
        }
    }

    private static SSLSocketFactory generate() throws IOException {
        Path dir = Files.createTempDirectory("druvu-jmxmp-ephemeral");
        Path store = dir.resolve("ephemeral.p12");
        try {
            generateKeystore(store);
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(store)) {
                ks.load(in, STORE_PASSWORD.toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, STORE_PASSWORD.toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            LOG.info(
                    "socketFactory",
                    "druvu-lib-jmxmp: no 'jmx.remote.tls.socket.factory' configured — generated an EPHEMERAL "
                            + "self-signed TLS certificate for this JVM. The JMXMP listener is encrypted, but the "
                            + "certificate is not verifiable by clients (encryption only, no server-identity / MITM "
                            + "protection). For production, set 'jmx.remote.tls.socket.factory' from a trusted keystore.");
            return ctx.getSocketFactory();
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Failed to generate an ephemeral self-signed TLS certificate", e);
        } finally {
            try {
                Files.deleteIfExists(store);
                Files.deleteIfExists(dir);
            } catch (IOException ignore) {
                // best effort — the private key already lives in the in-memory SSLContext, not the file
            }
        }
    }

    private static void generateKeystore(Path store) throws IOException {
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
                        "365",
                        "-storetype",
                        "PKCS12",
                        "-keystore",
                        store.toAbsolutePath().toString(),
                        "-storepass",
                        STORE_PASSWORD,
                        "-keypass",
                        STORE_PASSWORD)
                .redirectErrorStream(true)
                .start();
        String output;
        try (InputStream in = p.getInputStream()) {
            output = new String(in.readAllBytes());
        }
        int code;
        try {
            code = p.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while generating an ephemeral TLS certificate", e);
        }
        if (code != 0 || !Files.exists(store)) {
            throw new IOException("keytool could not generate an ephemeral TLS certificate (exit " + code
                    + "). Is keytool present in this runtime? Otherwise set 'jmx.remote.tls.socket.factory' explicitly."
                    + (output.isBlank() ? "" : " keytool output: " + output.trim()));
        }
    }
}
