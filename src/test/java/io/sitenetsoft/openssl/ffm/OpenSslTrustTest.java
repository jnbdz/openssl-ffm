package io.sitenetsoft.openssl.ffm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.junit.jupiter.api.Test;

class OpenSslTrustTest {

    @Test
    void clientVerifiesServerAndExposesItsCertificate() throws Exception {
        OpenSslEngine client = EnginePair.openSslClient("server-ec.p12");
        EnginePair pair = new EnginePair(client, EnginePair.jdkServer("server-ec.p12"));
        pair.handshake();

        X509Certificate expected = (X509Certificate) EnginePair.load("server-ec.p12").getCertificate("server");
        assertThat(client.getSession().getPeerCertificates()).hasSize(1);
        assertThat(client.getSession().getPeerCertificates()[0]).isEqualTo(expected);
        assertThat(client.getSession().getPeerPrincipal().getName()).isEqualTo("CN=localhost");
        pair.close();
    }

    @Test
    void untrustedServerIsRejected() throws Exception {
        EnginePair pair = new EnginePair(EnginePair.openSslClient("server-rsa.p12"), EnginePair.jdkServer("server-ec.p12"));

        assertThatThrownBy(pair::handshake).isInstanceOf(SSLHandshakeException.class)
                .hasCauseInstanceOf(CertificateException.class);
    }

    @Test
    void hostnameIsCheckedWithEndpointIdentification() throws Exception {
        OpenSslEngine client = EnginePair.openSslClient("server-ec.p12", null, "wrong.example");
        SSLParameters parameters = client.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        client.setSSLParameters(parameters);
        EnginePair pair = new EnginePair(client, EnginePair.jdkServer("server-ec.p12"));

        assertThatThrownBy(pair::handshake).isInstanceOf(SSLHandshakeException.class)
                .hasCauseInstanceOf(CertificateException.class);
    }

    @Test
    void hostnameIsNotCheckedWithoutEndpointIdentification() throws Exception {
        OpenSslEngine client = EnginePair.openSslClient("server-ec.p12", null, "wrong.example");
        EnginePair pair = new EnginePair(client, EnginePair.jdkServer("server-ec.p12"));
        pair.handshake();
        pair.close();
    }

    @Test
    void requiredClientCertificateIsMissing() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12", "client-ec.p12");
        server.setNeedClientAuth(true);
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", null, "TLSv1.3"), server);

        assertThatThrownBy(pair::handshake).isInstanceOf(SSLException.class);
    }

    @Test
    void requiredClientCertificateIsVerifiedTls13() throws Exception {
        assertMutualTls("TLSv1.3");
    }

    @Test
    void requiredClientCertificateIsVerifiedTls12() throws Exception {
        assertMutualTls("TLSv1.2");
    }

    private static void assertMutualTls(String protocol) throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12", "client-ec.p12");
        server.setNeedClientAuth(true);
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "client-ec.p12", protocol), server);
        pair.handshake();

        assertThat(server.getSession().getProtocol()).isEqualTo(protocol);
        assertThat(server.getSession().getPeerPrincipal().getName()).isEqualTo("CN=client");
        byte[] received = pair.send(pair.client, pair.server, "authenticated".getBytes());
        assertThat(new String(received)).isEqualTo("authenticated");
        pair.close();
    }

    @Test
    void untrustedClientCertificateIsRejected() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12", "server-rsa.p12");
        server.setNeedClientAuth(true);
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "client-ec.p12", "TLSv1.3"), server);

        assertThatThrownBy(pair::handshake).isInstanceOf(SSLException.class);
    }

    @Test
    void wantedClientCertificateMayBeMissing() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12", "client-ec.p12");
        server.setWantClientAuth(true);
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", null, "TLSv1.3"), server);
        pair.handshake();

        assertThatThrownBy(() -> server.getSession().getPeerCertificates())
                .isInstanceOf(SSLPeerUnverifiedException.class);
        pair.close();
    }
}
