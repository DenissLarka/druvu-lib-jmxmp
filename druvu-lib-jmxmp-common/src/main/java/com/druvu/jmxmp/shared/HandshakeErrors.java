/*
 * HandshakeErrors.java
 *
 * Extracted in the com.druvu fork (2.0) from AdminClient.throwExceptionOnError
 * so both the client (AdminClient) and server (AdminServer) handshake paths
 * can share it without a client<->server edge. Behaviour preserved from the
 * original Sun code (Copyright (c) 2007 Sun Microsystems, Inc.).
 * Dual-licensed: GPL v2 only with the Classpath exception, or CDDL v1.0.
 * See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.shared;

import java.io.IOException;
import javax.management.remote.message.HandshakeErrorMessage;

/** Shared handshake-error decoding (was {@code AdminClient.throwExceptionOnError}). */
public final class HandshakeErrors {

    private HandshakeErrors() {}

    public static void throwOnError(HandshakeErrorMessage error) throws IOException, SecurityException {
        final String detail = error.getDetail();
        if (detail.startsWith("java.lang.SecurityException")
                || detail.startsWith("java.security.")
                || detail.startsWith("javax.net.ssl.")
                || detail.startsWith("javax.security.")) {
            throw new SecurityException(detail);
        } else {
            throw new IOException(detail);
        }
    }
}
