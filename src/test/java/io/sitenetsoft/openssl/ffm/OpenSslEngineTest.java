package io.sitenetsoft.openssl.ffm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import javax.net.ssl.SSLException;

import org.junit.jupiter.api.Test;

class OpenSslEngineTest {

    @Test
    void tls13WithEcKey() throws Exception {
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"), EnginePair.openSslServer("server-ec.p12"));
        pair.handshake();

        assertThat(pair.server.getSession().getProtocol()).isEqualTo("TLSv1.3");
        assertThat(pair.client.getSession().getProtocol()).isEqualTo("TLSv1.3");
        assertThat(pair.server.getSession().getCipherSuite()).isEqualTo(pair.client.getSession().getCipherSuite());
        assertExchange(pair, "hello from the client", "hello from the server");
        String cipherSuite = pair.client.getSession().getCipherSuite();
        pair.close();

        assertThat(pair.server.getSession().getProtocol()).isEqualTo("TLSv1.3");
        assertThat(pair.server.getSession().getCipherSuite()).isEqualTo(cipherSuite);
    }

    @Test
    void tls12WithRsaKey() throws Exception {
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-rsa.p12", "TLSv1.2"), EnginePair.openSslServer("server-rsa.p12"));
        pair.handshake();

        assertThat(pair.server.getSession().getProtocol()).isEqualTo("TLSv1.2");
        assertThat(pair.server.getSession().getCipherSuite()).isEqualTo(pair.client.getSession().getCipherSuite())
                .startsWith("TLS_ECDHE_RSA_");
        assertExchange(pair, "ping", "pong");
        pair.close();
    }

    @Test
    void openSslClientWithJdkServer() throws Exception {
        OpenSslEngine client = EnginePair.openSslClient("server-ec.p12");
        EnginePair pair = new EnginePair(client, EnginePair.jdkServer("server-ec.p12"));
        pair.handshake();

        assertThat(client.getSession().getProtocol()).isEqualTo("TLSv1.3");
        assertExchange(pair, "request", "response");
        pair.close();
    }

    @Test
    void largeTransferBothWays() throws Exception {
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"), EnginePair.openSslServer("server-ec.p12"));
        pair.handshake();
        byte[] upload = new byte[1024 * 1024];
        byte[] download = new byte[1024 * 1024 + 17];
        new Random(42).nextBytes(upload);
        new Random(7).nextBytes(download);

        assertThat(pair.send(pair.client, pair.server, upload)).isEqualTo(upload);
        assertThat(pair.send(pair.server, pair.client, download)).isEqualTo(download);
        pair.close();
    }

    @Test
    void protocolMismatchFailsTheHandshake() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
        server.setEnabledProtocols(new String[] { "TLSv1.3" });
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.2"), server);

        assertThatThrownBy(pair::handshake).isInstanceOf(SSLException.class);
    }

    private static void assertExchange(EnginePair pair, String request, String response) throws Exception {
        byte[] received = pair.send(pair.client, pair.server, request.getBytes(StandardCharsets.UTF_8));
        assertThat(new String(received, StandardCharsets.UTF_8)).isEqualTo(request);
        received = pair.send(pair.server, pair.client, response.getBytes(StandardCharsets.UTF_8));
        assertThat(new String(received, StandardCharsets.UTF_8)).isEqualTo(response);
    }
}
