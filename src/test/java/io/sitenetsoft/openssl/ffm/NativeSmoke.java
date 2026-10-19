package io.sitenetsoft.openssl.ffm;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import javax.net.ssl.SSLException;

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
            EnginePair pair = new EnginePair(EnginePair.openSslClient(), EnginePair.jdkServer("server-ec.p12"));
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
