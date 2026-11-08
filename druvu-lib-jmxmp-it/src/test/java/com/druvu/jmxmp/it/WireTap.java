package com.druvu.jmxmp.it;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A TCP relay between a client and a server that keeps a copy of every byte the client sends. Once TLS starts, those
 * bytes are ciphertext, so a text found in the copy crossed the wire in clear.
 */
final class WireTap implements AutoCloseable {

    private final ServerSocket listener;
    private final String serverHost;
    private final int serverPort;
    private final ByteArrayOutputStream sentByClient = new ByteArrayOutputStream();
    private final List<Socket> relayed = new CopyOnWriteArrayList<>();

    WireTap(String serverHost, int serverPort) throws IOException {
        this.serverHost = serverHost;
        this.serverPort = serverPort;
        this.listener = new ServerSocket(0);
        Thread.ofPlatform().daemon().name("wire-tap").start(this::relayEachConnection);
    }

    /** The port a client connects to instead of the server's. */
    int port() {
        return listener.getLocalPort();
    }

    /** Whether the client sent {@code text} in clear, as its ASCII bytes. */
    boolean sawInClear(String text) {
        byte[] sent;
        synchronized (sentByClient) {
            sent = sentByClient.toByteArray();
        }
        // Latin-1 maps each byte to one char, so a substring search over it is a byte search.
        return new String(sent, StandardCharsets.ISO_8859_1).contains(text);
    }

    /** Closes every connection relayed so far, as a network failure would; the tap keeps accepting new ones. */
    void dropConnections() throws IOException {
        for (Socket socket : relayed) {
            socket.close();
        }
        relayed.clear();
    }

    @Override
    public void close() throws IOException {
        listener.close();
    }

    private void relayEachConnection() {
        while (!listener.isClosed()) {
            try {
                Socket client = listener.accept();
                Socket server = new Socket(serverHost, serverPort);
                relayed.add(client);
                relayed.add(server);
                copy(client, server, true);
                copy(server, client, false);
            } catch (IOException listenerClosed) {
                return;
            }
        }
    }

    /** Copies one direction until either side hangs up, then closes both sockets so the other direction ends too. */
    private void copy(Socket from, Socket to, boolean keepCopy) {
        Thread.ofPlatform().daemon().name("wire-tap-copy").start(() -> {
            byte[] buffer = new byte[8192];
            try (from;
                    to) {
                InputStream in = from.getInputStream();
                OutputStream out = to.getOutputStream();
                for (int n = in.read(buffer); n > 0; n = in.read(buffer)) {
                    if (keepCopy) {
                        synchronized (sentByClient) {
                            sentByClient.write(buffer, 0, n);
                        }
                    }
                    out.write(buffer, 0, n);
                    out.flush();
                }
            } catch (IOException hungUp) {
                // one side closed the connection: the relay for it ends here
            }
        });
    }
}
