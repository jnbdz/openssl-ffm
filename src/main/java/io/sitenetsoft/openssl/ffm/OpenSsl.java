package io.sitenetsoft.openssl.ffm;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;

/**
 * Downcalls into the system {@code libssl} and {@code libcrypto}.
 * <p>
 * The handles live in {@link Handles}, which must be initialized at run time in a native executable.
 * C {@code long}, {@code unsigned long} and {@code size_t} are mapped to {@code long}, which assumes an LP64 platform.
 */
final class OpenSsl {

    static final int SSL_ERROR_NONE = 0;
    static final int SSL_ERROR_SSL = 1;
    static final int SSL_ERROR_WANT_READ = 2;
    static final int SSL_ERROR_WANT_WRITE = 3;
    static final int SSL_ERROR_SYSCALL = 5;
    static final int SSL_ERROR_ZERO_RETURN = 6;

    static final int SSL_SENT_SHUTDOWN = 1;
    static final int SSL_RECEIVED_SHUTDOWN = 2;

    static final int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
    static final int SSL_CTRL_CHAIN_CERT = 89;
    static final int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    static final int SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
    static final int TLSEXT_NAMETYPE_host_name = 0;

    static final int TLS1_2_VERSION = 0x0303;
    static final int TLS1_3_VERSION = 0x0304;

    private OpenSsl() {
    }

    static final class Handles {
        private static final Linker LINKER = Linker.nativeLinker();
        private static final SymbolLookup LIBS = libraries();

        static final MethodHandle OpenSSL_version_num = handle("OpenSSL_version_num", FunctionDescriptor.of(JAVA_LONG));
        static final MethodHandle OPENSSL_init_ssl = handle("OPENSSL_init_ssl",
                FunctionDescriptor.of(JAVA_INT, JAVA_LONG, ADDRESS));
        static final MethodHandle TLS_method = handle("TLS_method", FunctionDescriptor.of(ADDRESS));
        static final MethodHandle SSL_CTX_new = handle("SSL_CTX_new", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle SSL_CTX_free = handle("SSL_CTX_free", FunctionDescriptor.ofVoid(ADDRESS));
        static final MethodHandle SSL_CTX_ctrl = handle("SSL_CTX_ctrl",
                FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_INT, JAVA_LONG, ADDRESS));
        static final MethodHandle SSL_CTX_use_certificate = handle("SSL_CTX_use_certificate",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle SSL_CTX_use_PrivateKey = handle("SSL_CTX_use_PrivateKey",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle SSL_CTX_check_private_key = handle("SSL_CTX_check_private_key",
                FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle d2i_X509 = handle("d2i_X509",
                FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG));
        static final MethodHandle X509_free = handle("X509_free", FunctionDescriptor.ofVoid(ADDRESS));
        static final MethodHandle d2i_AutoPrivateKey = handle("d2i_AutoPrivateKey",
                FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG));
        static final MethodHandle EVP_PKEY_free = handle("EVP_PKEY_free", FunctionDescriptor.ofVoid(ADDRESS));
        static final MethodHandle SSL_new = handle("SSL_new", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle SSL_free = handle("SSL_free", FunctionDescriptor.ofVoid(ADDRESS));
        static final MethodHandle SSL_ctrl = handle("SSL_ctrl",
                FunctionDescriptor.of(JAVA_LONG, ADDRESS, JAVA_INT, JAVA_LONG, ADDRESS));
        static final MethodHandle SSL_set_accept_state = handle("SSL_set_accept_state", FunctionDescriptor.ofVoid(ADDRESS));
        static final MethodHandle SSL_set_connect_state = handle("SSL_set_connect_state",
                FunctionDescriptor.ofVoid(ADDRESS));
        static final MethodHandle SSL_set_bio = handle("SSL_set_bio", FunctionDescriptor.ofVoid(ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle SSL_do_handshake = handle("SSL_do_handshake", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle SSL_is_init_finished = handle("SSL_is_init_finished",
                FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle SSL_read = handle("SSL_read", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle SSL_write = handle("SSL_write",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle SSL_pending = handle("SSL_pending", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle SSL_get_error = handle("SSL_get_error", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle SSL_shutdown = handle("SSL_shutdown", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle SSL_get_shutdown = handle("SSL_get_shutdown", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle SSL_get_version = handle("SSL_get_version", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle SSL_get_current_cipher = handle("SSL_get_current_cipher",
                FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle SSL_CIPHER_standard_name = handle("SSL_CIPHER_standard_name",
                FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle BIO_new_bio_pair = handle("BIO_new_bio_pair",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_LONG, ADDRESS, JAVA_LONG));
        static final MethodHandle BIO_read = handle("BIO_read", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle BIO_write = handle("BIO_write",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle BIO_ctrl_pending = handle("BIO_ctrl_pending", FunctionDescriptor.of(JAVA_LONG, ADDRESS));
        static final MethodHandle BIO_free = handle("BIO_free", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle ERR_get_error = handle("ERR_get_error", FunctionDescriptor.of(JAVA_LONG));
        static final MethodHandle ERR_error_string_n = handle("ERR_error_string_n",
                FunctionDescriptor.ofVoid(JAVA_LONG, ADDRESS, JAVA_LONG));
        static final MethodHandle ERR_clear_error = handle("ERR_clear_error", FunctionDescriptor.ofVoid());

        private Handles() {
        }

        private static SymbolLookup libraries() {
            SymbolLookup ssl = open("openssl.ffm.libssl", List.of("libssl.so.3", "libssl.3.dylib", "libssl.so"));
            SymbolLookup crypto = open("openssl.ffm.libcrypto",
                    List.of("libcrypto.so.3", "libcrypto.3.dylib", "libcrypto.so"));
            return ssl.or(crypto);
        }

        private static SymbolLookup open(String property, List<String> defaults) {
            List<String> names = new ArrayList<>();
            String configured = System.getProperty(property);
            if (configured != null) {
                names.add(configured);
            }
            names.addAll(defaults);
            IllegalArgumentException failure = null;
            for (String name : names) {
                try {
                    return SymbolLookup.libraryLookup(name, Arena.global());
                } catch (IllegalArgumentException e) {
                    failure = e;
                }
            }
            throw new UnsatisfiedLinkError("Cannot load any of " + names + ": " + failure.getMessage());
        }

        private static MethodHandle handle(String name, FunctionDescriptor descriptor) {
            MemorySegment symbol = LIBS.find(name).orElseThrow(() -> new UnsatisfiedLinkError("Missing symbol " + name));
            return LINKER.downcallHandle(symbol, descriptor);
        }
    }

    static String lastError() {
        try {
            long code = (long) Handles.ERR_get_error.invokeExact();
            if (code == 0) {
                return null;
            }
            StringBuilder message = new StringBuilder();
            try (Arena arena = Arena.ofConfined()) {
                MemorySegment buf = arena.allocate(256);
                while (code != 0) {
                    Handles.ERR_error_string_n.invokeExact(code, buf, 256L);
                    if (!message.isEmpty()) {
                        message.append("; ");
                    }
                    message.append(buf.getString(0));
                    code = (long) Handles.ERR_get_error.invokeExact();
                }
            }
            return message.toString();
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static void clearError() {
        try {
            Handles.ERR_clear_error.invokeExact();
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException re) {
            throw re;
        }
        if (t instanceof Error e) {
            throw e;
        }
        throw new IllegalStateException(t);
    }
}
