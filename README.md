# OpenSSL SSLEngine over FFM (prototype)

A prototype `javax.net.ssl.SSLEngine` backed by the system OpenSSL (`libssl.so.3`) through the Foreign Function & Memory API, written to explore [quarkusio/quarkus#57249](https://github.com/quarkusio/quarkus/issues/57249): using the system TLS library in Quarkus native executables.

Status: prototype, not for production use.

## What it does

- `OpenSslProvider` ("OpenSSL-FFM") provides `SSLContext.TLS`, which creates `OpenSslEngine` instances (engines only, no sockets).
- TLS 1.2 and 1.3, client and server mode, through an OpenSSL BIO pair, one TLS record per `unwrap`.
- Peer certificates are checked by the application's `X509TrustManager`, called from an OpenSSL verify callback; client authentication (need/want).
- ALPN, including the handshake application protocol selector.
- Cipher suites from the OpenSSL library, configurable by their IANA names.

Not done: session resumption, renegotiation and post-handshake authentication, `SSLSocket`, platforms other than Linux x86_64, performance measurements. Hostname checks need an `X509ExtendedTrustManager`.

## Native executables

`src/main/resources/META-INF/native-image/.../reachability-metadata.json` lists the downcall and upcall signatures and the callback methods registered for reflection. The classes holding method handles must be initialized at run time, and `Arena.ofShared()` is avoided because it needs `-H:+SharedArenaSupport`.

## Running

JUnit tests (JDK 22+, OpenSSL 3 installed):

```
mvn test
```

The same scenarios without JUnit, for a native executable (`NativeSmoke`):

```
mvn test-compile
native-image -cp target/classes:target/test-classes -H:+UnlockExperimentalVMOptions -H:IncludeResources='.*\.p12$' \
  --enable-native-access=ALL-UNNAMED -o smoke io.sitenetsoft.openssl.ffm.NativeSmoke
./smoke
```

Results (October 2026): all JUnit tests pass on JDK 25 with OpenSSL 3.6.4, and all 14 `NativeSmoke` scenarios pass in a Mandrel 25.0.4.1 native executable run in `registry.access.redhat.com/ubi10/ubi-minimal` (OpenSSL 3.5.8).

The `.p12` files under `src/test/resources` are self-signed test keys with the password `password`.

## License

Apache License 2.0.
