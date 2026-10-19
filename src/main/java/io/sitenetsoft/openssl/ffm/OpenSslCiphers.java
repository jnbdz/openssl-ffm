package io.sitenetsoft.openssl.ffm;

import static io.sitenetsoft.openssl.ffm.OpenSsl.Handles;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The cipher suites of the system OpenSSL, by IANA name.
 */
final class OpenSslCiphers {

    record Suite(String iana, String openssl, boolean tls13) {
    }

    private OpenSslCiphers() {
    }

    static Suite find(String iana) {
        return Table.SUPPORTED.get(iana);
    }

    static String[] supported() {
        return Table.SUPPORTED.keySet().toArray(String[]::new);
    }

    static String[] defaults() {
        return Table.DEFAULTS.toArray(String[]::new);
    }

    private static final class Table {
        static final Map<String, Suite> SUPPORTED = Collections.unmodifiableMap(load("ALL"));
        static final List<String> DEFAULTS = List.copyOf(load(null).keySet());

        private Table() {
        }

        private static Map<String, Suite> load(String cipherList) {
            try {
                OpenSslContext.init();
                MemorySegment method = (MemorySegment) Handles.TLS_method.invokeExact();
                MemorySegment ctx = (MemorySegment) Handles.SSL_CTX_new.invokeExact(method);
                MemorySegment ssl = MemorySegment.NULL;
                try {
                    if (cipherList != null) {
                        try (Arena arena = Arena.ofConfined()) {
                            int ignored = (int) Handles.SSL_CTX_set_cipher_list.invokeExact(ctx,
                                    arena.allocateFrom(cipherList));
                        }
                    }
                    ssl = (MemorySegment) Handles.SSL_new.invokeExact(ctx);
                    MemorySegment stack = (MemorySegment) Handles.SSL_get_ciphers.invokeExact(ssl);
                    int count = (int) Handles.OPENSSL_sk_num.invokeExact(stack);
                    Map<String, Suite> suites = new LinkedHashMap<>();
                    for (int i = 0; i < count; i++) {
                        MemorySegment cipher = (MemorySegment) Handles.OPENSSL_sk_value.invokeExact(stack, i);
                        String iana = string((MemorySegment) Handles.SSL_CIPHER_standard_name.invokeExact(cipher));
                        String name = string((MemorySegment) Handles.SSL_CIPHER_get_name.invokeExact(cipher));
                        String version = string((MemorySegment) Handles.SSL_CIPHER_get_version.invokeExact(cipher));
                        if (iana != null && name != null) {
                            suites.put(iana, new Suite(iana, name, "TLSv1.3".equals(version)));
                        }
                    }
                    return suites;
                } finally {
                    if (!ssl.equals(MemorySegment.NULL)) {
                        Handles.SSL_free.invokeExact(ssl);
                    }
                    Handles.SSL_CTX_free.invokeExact(ctx);
                }
            } catch (Throwable t) {
                throw OpenSsl.rethrow(t);
            }
        }

        private static String string(MemorySegment pointer) {
            return pointer.equals(MemorySegment.NULL) ? null
                    : pointer.reinterpret(256).getString(0, StandardCharsets.US_ASCII);
        }
    }

    static List<String> openSslNames(List<Suite> suites, boolean tls13) {
        List<String> names = new ArrayList<>();
        for (Suite suite : suites) {
            if (suite.tls13() == tls13) {
                names.add(tls13 ? suite.iana() : suite.openssl());
            }
        }
        return names;
    }
}
