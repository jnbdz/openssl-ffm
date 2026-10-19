package io.sitenetsoft.openssl.ffm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.junit.jupiter.api.Test;

class OpenSslAlpnTest {

    @Test
    void serverSelectsH2() throws Exception {
        OpenSslEngine server = applicationProtocols(EnginePair.openSslServer("server-ec.p12"), "h2", "http/1.1");
        SSLEngine client = EnginePair.jdkClient("server-ec.p12", null, "TLSv1.3", "h2", "http/1.1");
        EnginePair pair = new EnginePair(client, server);
        pair.handshake();

        assertThat(server.getApplicationProtocol()).isEqualTo("h2");
        assertThat(client.getApplicationProtocol()).isEqualTo("h2");
        pair.close();
    }

    @Test
    void serverPreferenceWins() throws Exception {
        OpenSslEngine server = applicationProtocols(EnginePair.openSslServer("server-ec.p12"), "http/1.1");
        SSLEngine client = EnginePair.jdkClient("server-ec.p12", null, "TLSv1.2", "h2", "http/1.1");
        EnginePair pair = new EnginePair(client, server);
        pair.handshake();

        assertThat(server.getApplicationProtocol()).isEqualTo("http/1.1");
        assertThat(client.getApplicationProtocol()).isEqualTo("http/1.1");
    }

    @Test
    void selectorIsUsed() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
        server.setHandshakeApplicationProtocolSelector(
                (engine, offered) -> offered.contains("http/1.1") ? "http/1.1" : null);
        SSLEngine client = EnginePair.jdkClient("server-ec.p12", null, "TLSv1.3", "h2", "http/1.1");
        EnginePair pair = new EnginePair(client, server);
        pair.handshake();

        assertThat(client.getApplicationProtocol()).isEqualTo("http/1.1");
    }

    @Test
    void clientOffersH2ToJdkServer() throws Exception {
        OpenSslEngine client = applicationProtocols(EnginePair.openSslClient("server-ec.p12"), "h2", "http/1.1");
        SSLEngine server = EnginePair.jdkServer("server-ec.p12");
        SSLParameters parameters = server.getSSLParameters();
        parameters.setApplicationProtocols(new String[] { "h2" });
        server.setSSLParameters(parameters);
        EnginePair pair = new EnginePair(client, server);
        pair.handshake();

        assertThat(client.getApplicationProtocol()).isEqualTo("h2");
        assertThat(server.getApplicationProtocol()).isEqualTo("h2");
    }

    @Test
    void withoutAlpnTheProtocolIsEmpty() throws Exception {
        OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
        assertThat(server.getApplicationProtocol()).isNull();
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"), server);
        pair.handshake();

        assertThat(server.getApplicationProtocol()).isEmpty();
    }

    @Test
    void noCommonProtocolFailsTheHandshake() throws Exception {
        OpenSslEngine server = applicationProtocols(EnginePair.openSslServer("server-ec.p12"), "spdy/3");
        EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", null, "TLSv1.3", "h2"), server);

        assertThatThrownBy(pair::handshake).isInstanceOf(SSLException.class);
    }

    private static OpenSslEngine applicationProtocols(OpenSslEngine engine, String... protocols) {
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setApplicationProtocols(protocols);
        engine.setSSLParameters(parameters);
        return engine;
    }
}
