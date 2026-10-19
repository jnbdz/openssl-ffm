package io.sitenetsoft.openssl.ffm;

import static io.sitenetsoft.openssl.ffm.OpenSsl.Handles;

import java.io.ByteArrayInputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Conversions from OpenSSL {@code X509} objects to Java certificates.
 */
final class OpenSslCertificates {

    private OpenSslCertificates() {
    }

    static X509Certificate toJava(MemorySegment x509) throws Throwable {
        int length = (int) Handles.i2d_X509.invokeExact(x509, MemorySegment.NULL);
        if (length <= 0) {
            throw new CertificateException("i2d_X509 failed: " + OpenSsl.lastError());
        }
        byte[] der;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buffer = arena.allocate(length);
            MemorySegment cursor = arena.allocateFrom(ValueLayout.ADDRESS, buffer);
            int written = (int) Handles.i2d_X509.invokeExact(x509, cursor);
            if (written != length) {
                throw new CertificateException("i2d_X509 wrote " + written + " of " + length + " bytes");
            }
            der = buffer.toArray(ValueLayout.JAVA_BYTE);
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * The leaf followed by the other certificates of {@code stack}, without duplicates of the leaf.
     */
    static X509Certificate[] chain(MemorySegment leaf, MemorySegment stack) throws Throwable {
        List<X509Certificate> chain = new ArrayList<>();
        X509Certificate first = leaf.equals(MemorySegment.NULL) ? null : toJava(leaf);
        if (first != null) {
            chain.add(first);
        }
        if (!stack.equals(MemorySegment.NULL)) {
            int count = (int) Handles.OPENSSL_sk_num.invokeExact(stack);
            for (int i = 0; i < count; i++) {
                MemorySegment element = (MemorySegment) Handles.OPENSSL_sk_value.invokeExact(stack, i);
                X509Certificate certificate = toJava(element);
                if (first == null || !Arrays.equals(certificate.getEncoded(), first.getEncoded())) {
                    chain.add(certificate);
                }
            }
        }
        return chain.toArray(X509Certificate[]::new);
    }
}
