/*
 * ServerConfig.java
 *
 * New in the com.druvu fork (3.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.server.internal;

import com.druvu.jmxmp.server.security.ServerAdminImpl;
import java.util.Map;

/**
 * The env lookups only the server reads; the ones both sides read are in {@code DefaultConfig} of the common module.
 * The env key keeps its OpenDMK name.
 *
 * @author Deniss Larka <br>
 *     on 08 Nov 2026
 */
public final class ServerConfig {

    /** The env key of a {@link ServerAdmin} that replaces the default handshake, {@link ServerAdminImpl}. */
    public static final String SERVER_ADMIN = "com.sun.jmx.remote.server.admin";

    private ServerConfig() {}

    /**
     * The {@link ServerAdmin} under {@link #SERVER_ADMIN}, else a new {@link ServerAdminImpl} over the same env.
     *
     * @throws IllegalArgumentException if the env holds something else under the key
     */
    public static ServerAdmin getServerAdmin(Map env) {
        Object admin = env.get(SERVER_ADMIN);
        if (admin == null) {
            return new ServerAdminImpl(env);
        }
        if (admin instanceof ServerAdmin serverAdmin) {
            return serverAdmin;
        }
        throw new IllegalArgumentException(
                "The specified attribute \"" + SERVER_ADMIN + "\" is not a ServerAdmin object.");
    }
}
