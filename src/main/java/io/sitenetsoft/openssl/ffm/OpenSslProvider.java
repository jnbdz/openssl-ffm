package io.sitenetsoft.openssl.ffm;

import java.security.Provider;
import java.util.List;

/**
 * A JSSE provider whose {@code SSLContext} uses the system OpenSSL through the FFM API.
 */
public final class OpenSslProvider extends Provider {

    public static final String NAME = "OpenSSL-FFM";

    public OpenSslProvider() {
        super(NAME, "0.1", "TLS through the system OpenSSL, using the Foreign Function & Memory API");
        putService(new Service(this, "SSLContext", "TLS", OpenSslContextSpi.class.getName(),
                List.of("TLSv1.2", "TLSv1.3"), null));
    }
}
