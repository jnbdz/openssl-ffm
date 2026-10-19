package io.sitenetsoft.openssl.ffm;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/**
 * Runs the engine scenarios without JUnit, for native executables.
 */
public final class NativeSmoke {

    private NativeSmoke() {
    }

    public static void main(String[] args) throws Throwable {
        long version = (long) OpenSsl.Handles.OpenSSL_version_num.invokeExact();
        System.out.printf("OpenSSL_version_num=0x%x%n", version);
        int failures = 0;
        failures += run("tls13 EC, JDK client", () -> {
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"),
                    EnginePair.openSslServer("server-ec.p12"));
            pair.handshake();
            exchange(pair, "hello", "world");
            pair.close();
            return pair.server.getSession().getProtocol() + " " + pair.server.getSession().getCipherSuite();
        });
        failures += run("tls12 RSA, JDK client", () -> {
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-rsa.p12", "TLSv1.2"),
                    EnginePair.openSslServer("server-rsa.p12"));
            pair.handshake();
            exchange(pair, "ping", "pong");
            pair.close();
            return pair.server.getSession().getProtocol() + " " + pair.server.getSession().getCipherSuite();
        });
        failures += run("tls13, OpenSSL client, JDK server", () -> {
            EnginePair pair = new EnginePair(EnginePair.openSslClient("server-ec.p12"), EnginePair.jdkServer("server-ec.p12"));
            pair.handshake();
            exchange(pair, "request", "response");
            pair.close();
            return pair.client.getSession().getProtocol() + " " + pair.client.getSession().getCipherSuite();
        });
        failures += run("1 MiB both ways", () -> {
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"),
                    EnginePair.openSslServer("server-ec.p12"));
            pair.handshake();
            byte[] up = new byte[1024 * 1024];
            byte[] down = new byte[1024 * 1024 + 17];
            new Random(42).nextBytes(up);
            new Random(7).nextBytes(down);
            EnginePair.check(Arrays.equals(pair.send(pair.client, pair.server, up), up), "upload");
            EnginePair.check(Arrays.equals(pair.send(pair.server, pair.client, down), down), "download");
            pair.close();
            return "ok";
        });
        failures += run("protocol mismatch fails", () -> {
            OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
            server.setEnabledProtocols(new String[] { "TLSv1.3" });
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.2"), server);
            try {
                pair.handshake();
            } catch (SSLException expected) {
                return "failed as expected: " + expected.getMessage();
            }
            throw new AssertionError("handshake succeeded");
        });
        failures += run("client verifies the server", () -> {
            OpenSslEngine client = EnginePair.openSslClient("server-ec.p12");
            EnginePair pair = new EnginePair(client, EnginePair.jdkServer("server-ec.p12"));
            pair.handshake();
            pair.close();
            return "peer " + ((X509Certificate) client.getSession().getPeerCertificates()[0]).getSubjectX500Principal();
        });
        failures += run("untrusted server rejected", () -> expectVerifyFailure(
                new EnginePair(EnginePair.openSslClient("server-rsa.p12"), EnginePair.jdkServer("server-ec.p12"))));
        failures += run("hostname mismatch rejected", () -> {
            OpenSslEngine client = EnginePair.openSslClient("server-ec.p12", null, "wrong.example");
            SSLParameters parameters = client.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            client.setSSLParameters(parameters);
            return expectVerifyFailure(new EnginePair(client, EnginePair.jdkServer("server-ec.p12")));
        });
        failures += run("mutual TLS 1.3", () -> {
            OpenSslEngine server = EnginePair.openSslServer("server-ec.p12", "client-ec.p12");
            server.setNeedClientAuth(true);
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "client-ec.p12", "TLSv1.3"), server);
            pair.handshake();
            exchange(pair, "authenticated", "welcome");
            pair.close();
            return "peer " + server.getSession().getPeerPrincipal();
        });
        failures += run("missing client certificate rejected", () -> {
            OpenSslEngine server = EnginePair.openSslServer("server-ec.p12", "client-ec.p12");
            server.setNeedClientAuth(true);
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", null, "TLSv1.3"), server);
            try {
                pair.handshake();
            } catch (SSLException expected) {
                return "failed as expected: " + expected.getMessage();
            }
            throw new AssertionError("handshake succeeded");
        });
        failures += run("ALPN h2, OpenSSL server", () -> {
            OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
            SSLParameters parameters = server.getSSLParameters();
            parameters.setApplicationProtocols(new String[] { "h2", "http/1.1" });
            server.setSSLParameters(parameters);
            SSLEngine client = EnginePair.jdkClient("server-ec.p12", null, "TLSv1.3", "h2", "http/1.1");
            EnginePair pair = new EnginePair(client, server);
            pair.handshake();
            EnginePair.check("h2".equals(server.getApplicationProtocol()), "server ALPN " + server.getApplicationProtocol());
            EnginePair.check("h2".equals(client.getApplicationProtocol()), "client ALPN " + client.getApplicationProtocol());
            return "h2";
        });
        failures += run("ALPN h2, OpenSSL client", () -> {
            OpenSslEngine client = EnginePair.openSslClient("server-ec.p12");
            SSLParameters parameters = client.getSSLParameters();
            parameters.setApplicationProtocols(new String[] { "h2", "http/1.1" });
            client.setSSLParameters(parameters);
            SSLEngine server = EnginePair.jdkServer("server-ec.p12");
            SSLParameters serverParameters = server.getSSLParameters();
            serverParameters.setApplicationProtocols(new String[] { "h2" });
            server.setSSLParameters(serverParameters);
            EnginePair pair = new EnginePair(client, server);
            pair.handshake();
            EnginePair.check("h2".equals(client.getApplicationProtocol()), "client ALPN " + client.getApplicationProtocol());
            return "h2";
        });
        failures += run("TLS 1.2 cipher suite applied", () -> {
            OpenSslEngine server = EnginePair.openSslServer("server-ec.p12");
            server.setEnabledCipherSuites(new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" });
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.2"), server);
            pair.handshake();
            String suite = server.getSession().getCipherSuite();
            EnginePair.check(suite.equals("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"), "suite " + suite);
            return suite + ", " + server.getSupportedCipherSuites().length + " supported";
        });
        failures += run("provider SSLContext", () -> {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(EnginePair.load("server-ec.p12"), "password".toCharArray());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(EnginePair.load("server-ec.p12"));
            SSLContext context = SSLContext.getInstance("TLS", new OpenSslProvider());
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLEngine server = context.createSSLEngine();
            server.setUseClientMode(false);
            EnginePair pair = new EnginePair(EnginePair.jdkClient("server-ec.p12", "TLSv1.3"), server);
            pair.handshake();
            exchange(pair, "via", "provider");
            pair.close();
            return context.getProvider().getName() + " " + server.getClass().getSimpleName();
        });
        System.out.println(failures == 0 ? "ALL PASSED" : failures + " FAILED");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static void exchange(EnginePair pair, String request, String response) throws Exception {
        String received = new String(pair.send(pair.client, pair.server, request.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8);
        EnginePair.check(received.equals(request), "request " + received);
        received = new String(pair.send(pair.server, pair.client, response.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8);
        EnginePair.check(received.equals(response), "response " + received);
    }

    private static String expectVerifyFailure(EnginePair pair) throws Exception {
        try {
            pair.handshake();
        } catch (SSLHandshakeException expected) {
            EnginePair.check(expected.getCause() instanceof CertificateException, "cause " + expected.getCause());
            return "rejected: " + expected.getCause().getMessage();
        }
        throw new AssertionError("handshake succeeded");
    }

    interface Scenario {
        String run() throws Exception;
    }

    private static int run(String name, Scenario scenario) {
        try {
            System.out.println("PASS " + name + ": " + scenario.run());
            return 0;
        } catch (Throwable t) {
            System.out.println("FAIL " + name + ": " + t);
            t.printStackTrace(System.out);
            return 1;
        }
    }
}
