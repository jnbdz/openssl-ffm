package io.sitenetsoft.openssl.ffm;

import java.util.Collections;
import java.util.Enumeration;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;

/**
 * A session context without a Java-side cache; OpenSSL keeps its own session cache.
 */
final class OpenSslSessionContext implements SSLSessionContext {

    private volatile int timeout = 86400;
    private volatile int cacheSize;

    @Override
    public SSLSession getSession(byte[] sessionId) {
        return null;
    }

    @Override
    public Enumeration<byte[]> getIds() {
        return Collections.emptyEnumeration();
    }

    @Override
    public void setSessionTimeout(int seconds) {
        timeout = seconds;
    }

    @Override
    public int getSessionTimeout() {
        return timeout;
    }

    @Override
    public void setSessionCacheSize(int size) {
        cacheSize = size;
    }

    @Override
    public int getSessionCacheSize() {
        return cacheSize;
    }
}
