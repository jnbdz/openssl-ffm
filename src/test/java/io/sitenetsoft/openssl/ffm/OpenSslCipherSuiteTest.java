package io.sitenetsoft.openssl.ffm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.net.ssl.SSLException;

import org.junit.jupiter.api.Test;

class OpenSslCipherSuiteTest {

    @Test
    void suitesComeFromOpenSsl() throws Exception {
        OpenSslEngine engine = EnginePair.openSslServer("server-ec.p12");

        assertThat(engine.getSupportedCipherSuites()).contains("TLS_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
        assertThat(engine.getEnabledCipherSuites()).isNotEmpty().contains("TLS_AES_256_GCM_SHA384");
        assertThat(engine.getSupportedCipherSuites()).contains(engine.getEnabledCipherSuites());
    }

    @Test
    void tls12SuiteIsApplied() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
        server.setEnabledCipherSuites(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" });
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.2"), server);
        pair.handshake();

        assertThat(server.getSession().getCipherSuite()).isEqualTo("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
        assertThat(pair.client.getSession().getCipherSuite()).isEqualTo("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    }

    @Test
    void tls13SuiteIsApplied() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
        server.setEnabledCipherSuites(new String[] { "TLS_CHACHA20_POLY1305_SHA256" });
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"), server);
        pair.handshake();

        assertThat(server.getSession().getProtocol()).isEqualTo("TLSv1.3");
        assertThat(pair.client.getSession().getCipherSuite()).isEqualTo("TLS_CHACHA20_POLY1305_SHA256");
    }

    @Test
    void onlyTls13SuitesDisableTls12() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
        server.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256" });
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.2"), server);

        assertThatThrownBy(pair::handshake).isInstanceOf(SSLException.class);
    }

    @Test
    void unknownSuiteIsRejected() throws Exception {
        OpenSslEngine engine = EnginePair.openSslServer("server-ec.p12");

        assertThatThrownBy(() -> engine.setEnabledCipherSuites(new String[] { "TLS_NOT_A_SUITE" }))
                .isInstanceOf(IllegalArgumentException.class);
        engine.setEnabledCipherSuites(new String[] { "TLS_AES_128_GCM_SHA256", "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" });
        assertThat(engine.getEnabledCipherSuites()).containsExactly("TLS_AES_128_GCM_SHA256");
    }
}
