package io.sitenetsoft.openssl.ffm;

import static io.sitenetsoft.openssl.ffm.OpenSsl.Handles;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * An OpenSSL {@code SSL_CTX}, holding the local key and certificate chain.
 * Peer certificates are checked by the Java trust manager, from OpenSSL's certificate verification callback.
 */
final class OpenSslContext implements AutoCloseable {

    private static volatile boolean initialized;

    private final MemorySegment ctx;
    private final X509Certificate[] chain;
    private final X509TrustManager trustManager;
    private boolean closed;

    OpenSslContext(PrivateKey key, X509Certificate[] chain) throws SSLException {
        this(key, chain, null);
    }

    OpenSslContext(PrivateKey key, X509Certificate[] chain, X509TrustManager trustManager) throws SSLException {
        init();
        this.chain = chain == null ? new X509Certificate[0] : chain.clone();
        this.trustManager = trustManager == null ? defaultTrustManager() : trustManager;
        try {
            OpenSsl.clearError();
            MemorySegment method = (MemorySegment) Handles.TLS_method.invokeExact();
            ctx = (MemorySegment) Handles.SSL_CTX_new.invokeExact(method);
            if (ctx.equals(MemorySegment.NULL)) {
                throw new SSLException("SSL_CTX_new failed: " + OpenSsl.lastError());
            }
            long rc = (long) Handles.SSL_CTX_ctrl.invokeExact(ctx, OpenSsl.SSL_CTRL_SET_MIN_PROTO_VERSION,
                    (long) OpenSsl.TLS1_2_VERSION, MemorySegment.NULL);
            if (rc != 1) {
                throw new SSLException("Cannot set the minimum protocol version: " + OpenSsl.lastError());
            }
            if (key != null) {
                useKeyAndChain(key);
            }
            Handles.SSL_CTX_set_cert_verify_callback.invokeExact(ctx, OpenSslCallbacks.Stubs.VERIFY, MemorySegment.NULL);
            Handles.SSL_CTX_set_alpn_select_cb.invokeExact(ctx, OpenSslCallbacks.Stubs.ALPN_SELECT, MemorySegment.NULL);
        } catch (SSLException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new SSLException(t);
        }
    }

    private void useKeyAndChain(PrivateKey key) throws Throwable {
        if (chain.length == 0) {
            throw new SSLException("A certificate chain is required with the private key");
        }
        MemorySegment x509 = decodeCertificate(chain[0]);
        try {
            if ((int) Handles.SSL_CTX_use_certificate.invokeExact(ctx, x509) != 1) {
                throw new SSLException("SSL_CTX_use_certificate failed: " + OpenSsl.lastError());
            }
        } finally {
            Handles.X509_free.invokeExact(x509);
        }
        for (int i = 1; i < chain.length; i++) {
            MemorySegment extra = decodeCertificate(chain[i]);
            // SSL_CTX_add0_chain_cert: the context takes ownership on success
            long rc = (long) Handles.SSL_CTX_ctrl.invokeExact(ctx, OpenSsl.SSL_CTRL_CHAIN_CERT, 0L, extra);
            if (rc != 1) {
                Handles.X509_free.invokeExact(extra);
                throw new SSLException("Cannot add a chain certificate: " + OpenSsl.lastError());
            }
        }
        byte[] pkcs8 = key.getEncoded();
        if (pkcs8 == null) {
            throw new SSLException("The private key " + key.getAlgorithm() + " cannot be encoded");
        }
        MemorySegment pkey = decode(pkcs8, Handles.d2i_AutoPrivateKey);
        try {
            if ((int) Handles.SSL_CTX_use_PrivateKey.invokeExact(ctx, pkey) != 1) {
                throw new SSLException("SSL_CTX_use_PrivateKey failed: " + OpenSsl.lastError());
            }
        } finally {
            Handles.EVP_PKEY_free.invokeExact(pkey);
        }
        if ((int) Handles.SSL_CTX_check_private_key.invokeExact(ctx) != 1) {
            throw new SSLException("The private key does not match the certificate: " + OpenSsl.lastError());
        }
    }

    private static MemorySegment decodeCertificate(X509Certificate certificate) throws Throwable {
        try {
            return decode(certificate.getEncoded(), Handles.d2i_X509);
        } catch (CertificateEncodingException e) {
            throw new SSLException(e);
        }
    }

    private static MemorySegment decode(byte[] der, java.lang.invoke.MethodHandle d2i) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocateFrom(ValueLayout.JAVA_BYTE, der);
            MemorySegment cursor = arena.allocateFrom(ValueLayout.ADDRESS, data);
            MemorySegment result = (MemorySegment) d2i.invokeExact(MemorySegment.NULL, cursor, (long) der.length);
            if (result.equals(MemorySegment.NULL)) {
                throw new SSLException("Cannot decode DER data: " + OpenSsl.lastError());
            }
            return result;
        }
    }

    private static X509TrustManager defaultTrustManager() throws SSLException {
        try {
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init((KeyStore) null);
            for (TrustManager manager : factory.getTrustManagers()) {
                if (manager instanceof X509TrustManager x509) {
                    return x509;
                }
            }
            throw new SSLException("No default X509TrustManager");
        } catch (NoSuchAlgorithmException | java.security.KeyStoreException e) {
            throw new SSLException(e);
        }
    }

    static void init() throws SSLException {
        if (initialized) {
            return;
        }
        synchronized (OpenSslContext.class) {
            if (initialized) {
                return;
            }
            try {
                if ((int) Handles.OPENSSL_init_ssl.invokeExact(0L, MemorySegment.NULL) != 1) {
                    throw new SSLException("OPENSSL_init_ssl failed: " + OpenSsl.lastError());
                }
            } catch (SSLException | RuntimeException | Error e) {
                throw e;
            } catch (Throwable t) {
                throw new SSLException(t);
            }
            initialized = true;
        }
    }

    MemorySegment ctx() {
        return ctx;
    }

    X509Certificate[] chain() {
        return chain.clone();
    }

    X509TrustManager trustManager() {
        return trustManager;
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            Handles.SSL_CTX_free.invokeExact(ctx);
        } catch (Throwable t) {
            throw OpenSsl.rethrow(t);
        }
    }
}
