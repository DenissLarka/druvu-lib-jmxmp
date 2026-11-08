/*
 * ClientConfig.java
 *
 * New in the com.druvu fork (3.0). New code, not Sun-derived.
 * Distributed under the project's dual license: GPL v2 only with the
 * Classpath exception, or CDDL v1.0. See the LICENSE file at the repo root.
 */

package com.druvu.jmxmp.client.internal;

import com.druvu.jmxmp.client.security.ClientAdminImpl;
import java.util.Map;

/**
 * The env lookups only the client reads; the ones both sides read are in {@code DefaultConfig} of the common module.
 * The env keys keep their OpenDMK names.
 *
 * @author Deniss Larka <br>
 *     on 08 Nov 2026
 */
public final class ClientConfig {

    /** The env key of a {@link ClientAdmin} that replaces the default handshake, {@link ClientAdminImpl}. */
    public static final String CLIENT_ADMIN = "com.sun.jmx.remote.client.admin";

    /** The env key of a ready {@link ClientSynchroMessageConnection}, used when the connector is given no socket. */
    public static final String CLIENT_SYNCHRO_MESSAGE_CONNECTION = "com.sun.jmx.remote.generic.synchro.client";

    private ClientConfig() {}

    /**
     * The {@link ClientAdmin} under {@link #CLIENT_ADMIN}, else a new {@link ClientAdminImpl} over the same env.
     *
     * @throws IllegalArgumentException if the env holds something else under the key
     */
    public static ClientAdmin getClientAdmin(Map env) {
        Object admin = env.get(CLIENT_ADMIN);
        if (admin == null) {
            return new ClientAdminImpl(env);
        }
        if (admin instanceof ClientAdmin clientAdmin) {
            return clientAdmin;
        }
        throw new IllegalArgumentException(
                "The specified attribute \"" + CLIENT_ADMIN + "\" is not a ClientAdmin object.");
    }

    /** The {@link ClientSynchroMessageConnection} under {@link #CLIENT_SYNCHRO_MESSAGE_CONNECTION}, or {@code null}. */
    public static ClientSynchroMessageConnection getClientSynchroMessageConnection(Map env) {
        return env == null ? null : (ClientSynchroMessageConnection) env.get(CLIENT_SYNCHRO_MESSAGE_CONNECTION);
    }
}
