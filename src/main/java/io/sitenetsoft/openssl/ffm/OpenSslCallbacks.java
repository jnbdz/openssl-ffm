package io.sitenetsoft.openssl.ffm;

import static io.sitenetsoft.openssl.ffm.OpenSsl.Handles;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Upcalls from OpenSSL into Java. The engine of a callback is found by the address of its {@code SSL} object.
 */
final class OpenSslCallbacks {

    private static final Map<Long, OpenSslEngine> ENGINES = new ConcurrentHashMap<>();

    private OpenSslCallbacks() {
    }

    static void register(MemorySegment ssl, OpenSslEngine engine) {
        ENGINES.put(ssl.address(), engine);
    }

    static void unregister(MemorySegment ssl) {
        ENGINES.remove(ssl.address());
    }

    static final class Stubs {
        // int (*)(X509_STORE_CTX *, void *)
        static final MemorySegment VERIFY = stub("verify", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS),
                MethodType.methodType(int.class, MemorySegment.class, MemorySegment.class));
        // int (*)(SSL *, const unsigned char **, unsigned char *, const unsigned char *, unsigned int, void *)
        static final MemorySegment ALPN_SELECT = stub("alpnSelect",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, JAVA_INT, ADDRESS),
                MethodType.methodType(int.class, MemorySegment.class, MemorySegment.class, MemorySegment.class,
                        MemorySegment.class, int.class, MemorySegment.class));
        private static final int SSL_INDEX = sslIndex();

        private Stubs() {
        }

        private static MemorySegment stub(String name, FunctionDescriptor descriptor, MethodType type) {
            try {
                return Linker.nativeLinker().upcallStub(
                        MethodHandles.lookup().findStatic(OpenSslCallbacks.class, name, type), descriptor, Arena.global());
            } catch (ReflectiveOperationException e) {
                throw new IllegalStateException(e);
            }
        }

        private static int sslIndex() {
            try {
                return (int) Handles.SSL_get_ex_data_X509_STORE_CTX_idx.invokeExact();
            } catch (Throwable t) {
                throw OpenSsl.rethrow(t);
            }
        }
    }

    static int verify(MemorySegment storeCtx, MemorySegment arg) {
        try {
            MemorySegment ssl = (MemorySegment) Handles.X509_STORE_CTX_get_ex_data.invokeExact(storeCtx, Stubs.SSL_INDEX);
            OpenSslEngine engine = ENGINES.get(ssl.address());
            return engine != null && engine.verifyPeer(storeCtx) ? 1 : 0;
        } catch (Throwable t) {
            return 0;
        }
    }

    static int alpnSelect(MemorySegment ssl, MemorySegment out, MemorySegment outLength, MemorySegment in,
            int inLength, MemorySegment arg) {
        try {
            OpenSslEngine engine = ENGINES.get(ssl.address());
            if (engine == null) {
                return OpenSsl.SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            return engine.selectApplicationProtocol(out.reinterpret(ADDRESS.byteSize()), outLength.reinterpret(1),
                    in.reinterpret(Integer.toUnsignedLong(inLength)));
        } catch (Throwable t) {
            return OpenSsl.SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }
}
