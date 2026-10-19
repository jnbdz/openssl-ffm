package io.sitenetsoft.openssl.ffm;

import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * The session of one {@link OpenSslEngine}.
 */
final class OpenSslSession implements SSLSession {

    private final OpenSslEngine engine;
    private final long creationTime = System.currentTimeMillis();
    private final Map<String, Object> values = new ConcurrentHashMap<>();

    OpenSslSession(OpenSslEngine engine) {
        this.engine = engine;
    }

    @Override
    public byte[] getId() {
        return new byte[0];
    }

    @Override
    public SSLSessionContext getSessionContext() {
        return null;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public long getLastAccessedTime() {
        return creationTime;
    }

    @Override
    public void invalidate() {
    }

    @Override
    public boolean isValid() {
        return true;
    }

    @Override
    public void putValue(String name, Object value) {
        values.put(name, value);
    }

    @Override
    public Object getValue(String name) {
        return values.get(name);
    }

    @Override
    public void removeValue(String name) {
        values.remove(name);
    }

    @Override
    public String[] getValueNames() {
        return values.keySet().toArray(String[]::new);
    }

    @Override
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        X509Certificate[] peer = engine.peerCertificates();
        if (peer == null || peer.length == 0) {
            throw new SSLPeerUnverifiedException("The peer is not authenticated");
        }
        return peer;
    }

    @Override
    public Certificate[] getLocalCertificates() {
        X509Certificate[] local = engine.localCertificates();
        return local.length == 0 ? null : local;
    }

    @Override
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return ((X509Certificate) getPeerCertificates()[0]).getSubjectX500Principal();
    }

    @Override
    public Principal getLocalPrincipal() {
        X509Certificate[] local = engine.localCertificates();
        return local.length == 0 ? null : local[0].getSubjectX500Principal();
    }

    @Override
    public String getCipherSuite() {
        return engine.cipherSuite();
    }

    @Override
    public String getProtocol() {
        return engine.protocol();
    }

    @Override
    public String getPeerHost() {
        return engine.getPeerHost();
    }

    @Override
    public int getPeerPort() {
        return engine.getPeerPort();
    }

    @Override
    public int getPacketBufferSize() {
        return OpenSslEngine.MAX_ENCRYPTED_PACKET_LENGTH;
    }

    @Override
    public int getApplicationBufferSize() {
        return OpenSslEngine.MAX_PLAINTEXT_LENGTH;
    }
}
