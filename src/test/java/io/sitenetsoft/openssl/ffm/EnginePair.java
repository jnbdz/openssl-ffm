package io.sitenetsoft.openssl.ffm;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Moves bytes between two engines through in-memory network buffers.
 * Plain checks instead of AssertJ, so that it also runs in a native executable.
 */
final class EnginePair {

    final SSLEngine client;
    final SSLEngine server;
    private final ByteBuffer clientToServer = ByteBuffer.allocate(64 * 1024);
    private final ByteBuffer serverToClient = ByteBuffer.allocate(64 * 1024);

    EnginePair(SSLEngine client, SSLEngine server) {
        this.client = client;
        this.server = server;
    }

    void handshake() throws Exception {
        client.beginHandshake();
        server.beginHandshake();
        boolean clientFinished = false;
        boolean serverFinished = false;
        for (int i = 0; i < 200 && !(clientFinished && serverFinished); i++) {
            clientFinished |= step(client, serverToClient, clientToServer);
            serverFinished |= step(server, clientToServer, serverToClient);
        }
        check(clientFinished, "client handshake finished");
        check(serverFinished, "server handshake finished");
    }

    private static boolean step(SSLEngine engine, ByteBuffer in, ByteBuffer out) throws Exception {
        boolean finished = false;
        for (int i = 0; i < 20; i++) {
            SSLEngineResult result;
            switch (engine.getHandshakeStatus()) {
                case NEED_WRAP -> result = engine.wrap(ByteBuffer.allocate(0), out);
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    in.flip();
                    result = engine.unwrap(in, ByteBuffer.allocate(OpenSslEngine.MAX_PLAINTEXT_LENGTH));
                    in.compact();
                    if (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        return finished;
                    }
                }
                case NEED_TASK -> {
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    continue;
                }
                default -> {
                    return finished;
                }
            }
            if (result.getHandshakeStatus() == HandshakeStatus.FINISHED) {
                finished = true;
            }
        }
        return finished;
    }

    byte[] send(SSLEngine from, SSLEngine to, byte[] data) throws Exception {
        ByteBuffer src = ByteBuffer.wrap(data);
        ByteBuffer net = ByteBuffer.allocate(from.getSession().getPacketBufferSize());
        ByteBuffer received = ByteBuffer.allocate(data.length + OpenSslEngine.MAX_PLAINTEXT_LENGTH);
        ByteBuffer pending = ByteBuffer.allocate(4 * 1024 * 1024);
        // bytes left from the handshake, such as TLS 1.3 session tickets, come first
        ByteBuffer leftover = from == client ? clientToServer : serverToClient;
        leftover.flip();
        pending.put(leftover);
        leftover.clear();
        while (src.hasRemaining()) {
            net.clear();
            SSLEngineResult result = from.wrap(src, net);
            check(result.getStatus() == SSLEngineResult.Status.OK, "wrap status " + result);
            net.flip();
            pending.put(net);
        }
        while (from.getHandshakeStatus() == HandshakeStatus.NEED_WRAP) {
            net.clear();
            from.wrap(ByteBuffer.allocate(0), net);
            net.flip();
            pending.put(net);
        }
        pending.flip();
        while (pending.hasRemaining()) {
            SSLEngineResult result = to.unwrap(pending, received);
            check(result.getStatus() == SSLEngineResult.Status.OK, "unwrap status " + result);
            if (result.bytesConsumed() == 0 && result.bytesProduced() == 0) {
                break;
            }
        }
        received.flip();
        byte[] bytes = new byte[received.remaining()];
        received.get(bytes);
        return bytes;
    }

    void close() throws Exception {
        drain(serverToClient, client);
        drain(clientToServer, server);
        client.closeOutbound();
        ByteBuffer net = ByteBuffer.allocate(client.getSession().getPacketBufferSize());
        client.wrap(ByteBuffer.allocate(0), net);
        net.flip();
        SSLEngineResult result = server.unwrap(net, ByteBuffer.allocate(OpenSslEngine.MAX_PLAINTEXT_LENGTH));
        check(result.getStatus() == SSLEngineResult.Status.CLOSED, "server unwrap of close_notify " + result);
        check(server.isInboundDone(), "server inbound done");
        server.closeOutbound();
        net.clear();
        server.wrap(ByteBuffer.allocate(0), net);
        net.flip();
        client.unwrap(net, ByteBuffer.allocate(OpenSslEngine.MAX_PLAINTEXT_LENGTH));
        check(client.isInboundDone(), "client inbound done");
        check(client.isOutboundDone(), "client outbound done");
        check(server.isOutboundDone(), "server outbound done");
    }

    /**
     * Delivers bytes left from the handshake, such as TLS 1.3 session tickets.
     */
    private static void drain(ByteBuffer pending, SSLEngine to) throws Exception {
        pending.flip();
        while (pending.hasRemaining()) {
            SSLEngineResult result = to.unwrap(pending, ByteBuffer.allocate(OpenSslEngine.MAX_PLAINTEXT_LENGTH));
            if (result.bytesConsumed() == 0) {
                break;
            }
        }
        pending.compact();
    }

    static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError("Check failed: " + what);
        }
    }

    static OpenSslEngine openSslServer(String keyStore) throws Exception {
        return openSslServer(keyStore, null);
    }

    static OpenSslEngine openSslServer(String keyStore, String trustStore) throws Exception {
        OpenSslEngine engine = new OpenSslEngine(context(keyStore, trustStore), null, -1);
        engine.setUseClientMode(false);
        return engine;
    }

    static OpenSslEngine openSslClient(String trustStore) throws Exception {
        return openSslClient(trustStore, null, "localhost");
    }

    static OpenSslEngine openSslClient(String trustStore, String keyStore, String host) throws Exception {
        OpenSslEngine engine = new OpenSslEngine(context(keyStore, trustStore), host, 8443);
        engine.setUseClientMode(true);
        return engine;
    }

    static OpenSslContext context(String keyStore, String trustStore) throws Exception {
        X509TrustManager trust = trustStore == null ? null : trustManager(trustStore);
        if (keyStore == null) {
            return new OpenSslContext(null, null, trust);
        }
        KeyStore ks = load(keyStore);
        String alias = ks.aliases().nextElement();
        PrivateKey key = (PrivateKey) ks.getKey(alias, "password".toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);
        return new OpenSslContext(key, Arrays.copyOf(chain, chain.length, X509Certificate[].class), trust);
    }

    static X509TrustManager trustManager(String trustStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(load(trustStore));
        for (TrustManager manager : tmf.getTrustManagers()) {
            if (manager instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new IllegalStateException("No X509TrustManager");
    }

    static SSLEngine jdkClient(String trustStore, String keyStore, String protocol, String... alpn) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(load(trustStore));
        KeyManagerFactory kmf = null;
        if (keyStore != null) {
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(load(keyStore), "password".toCharArray());
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf == null ? null : kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        SSLEngine engine = context.createSSLEngine("localhost", 8443);
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[] { protocol });
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        if (alpn.length > 0) {
            parameters.setApplicationProtocols(alpn);
        }
        engine.setSSLParameters(parameters);
        return engine;
    }

    static SSLEngine jdkClient(String trustStore, String protocol) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(load(trustStore));
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, tmf.getTrustManagers(), null);
        SSLEngine engine = context.createSSLEngine("localhost", 8443);
        engine.setUseClientMode(true);
        engine.setEnabledProtocols(new String[] { protocol });
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        engine.setSSLParameters(parameters);
        return engine;
    }

    static SSLEngine jdkServer(String keyStore) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(load(keyStore), "password".toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), null, null);
        SSLEngine engine = context.createSSLEngine();
        engine.setUseClientMode(false);
        return engine;
    }

    static KeyStore load(String name) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (InputStream in = EnginePair.class.getResourceAsStream("/" + name)) {
            ks.load(in, "password".toCharArray());
        }
        return ks;
    }
}
