package io.sitenetsoft.openssl.ffm;

import static org.assertj.core.api.Assertions.assertThat;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;

class OpenSslProviderTest {

    static SSLContext openSslContext() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(EnginePair.load("server-ec.p12"), "password".toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(EnginePair.load("server-ec.p12"));
        SSLContext context = SSLContext.getInstance("TLS", new OpenSslProvider());
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    @Test
    void serverEngineFromTheProvider() throws Exception {
        SSLContext context = openSslContext();
        assertThat(context.getProvider().getName()).isEqualTo("OpenSSL-FFM");
        SSLEngine server = context.createSSLEngine();
        server.setUseClientMode(false);
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"), server);
        pair.handshake();

        assertThat(server).isInstanceOf(OpenSslEngine.class);
        assertThat(server.getSession().getLocalCertificates()).hasSize(1);
        pair.close();
    }

    @Test
    void clientEngineFromTheProvider() throws Exception {
        SSLEngine client = openSslContext().createSSLEngine("localhost", 8443);
        client.setUseClientMode(true);
        EnginePair pair = new EnginePair(client, EnginePair.jdkServer("server-ec.p12"));
        pair.handshake();

        assertThat(client.getSession().getPeerCertificates()).hasSize(1);
        pair.close();
    }
}
