package io.sitenetsoft.openssl.ffm;

import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * The {@code SSLContext} of {@link OpenSslProvider}. Only {@link SSLEngine}s are supported, not sockets.
 */
public final class OpenSslContextSpi extends SSLContextSpi {

    private static final String[] KEY_TYPES = { "EC", "RSA" };

    private final OpenSslSessionContext clientSessions = new OpenSslSessionContext();
    private final OpenSslSessionContext serverSessions = new OpenSslSessionContext();
    private OpenSslContext serverContext;
    private OpenSslContext clientContext;

    public OpenSslContextSpi() {
    }

    @Override
    protected synchronized void engineInit(KeyManager[] keyManagers, TrustManager[] trustManagers, SecureRandom random)
            throws KeyManagementException {
        X509KeyManager keyManager = first(keyManagers, X509KeyManager.class);
        X509TrustManager trustManager = first(trustManagers, X509TrustManager.class);
        try {
            serverContext = context(keyManager, serverAlias(keyManager), trustManager);
            clientContext = context(keyManager,
                    keyManager == null ? null : keyManager.chooseClientAlias(KEY_TYPES, null, null), trustManager);
        } catch (SSLException e) {
            throw new KeyManagementException(e);
        }
    }

    private static String serverAlias(X509KeyManager keyManager) {
        if (keyManager == null) {
            return null;
        }
        for (String type : KEY_TYPES) {
            String alias = keyManager.chooseServerAlias(type, null, null);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    private static OpenSslContext context(X509KeyManager keyManager, String alias, X509TrustManager trustManager)
            throws SSLException {
        if (alias == null) {
            return new OpenSslContext(null, null, trustManager);
        }
        PrivateKey key = keyManager.getPrivateKey(alias);
        X509Certificate[] chain = keyManager.getCertificateChain(alias);
        return new OpenSslContext(key, chain, trustManager);
    }

    private static <T> T first(Object[] managers, Class<T> type) {
        if (managers != null) {
            for (Object manager : managers) {
                if (type.isInstance(manager)) {
                    return type.cast(manager);
                }
            }
        }
        return null;
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return engineCreateSSLEngine(null, -1);
    }

    @Override
    protected synchronized SSLEngine engineCreateSSLEngine(String host, int port) {
        if (serverContext == null) {
            throw new IllegalStateException("SSLContext is not initialized");
        }
        return new OpenSslEngine(serverContext, clientContext, host, port);
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        throw new UnsupportedOperationException("Only SSLEngine is supported");
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        throw new UnsupportedOperationException("Only SSLEngine is supported");
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return serverSessions;
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return clientSessions;
    }
}
