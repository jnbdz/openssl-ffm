package io.sitenetsoft.openssl.ffm;

import static io.sitenetsoft.openssl.ffm.OpenSsl.Handles;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * An {@link SSLEngine} backed by an OpenSSL {@code SSL} object and a BIO pair.
 */
final class OpenSslEngine extends SSLEngine {

    static final int MAX_PLAINTEXT_LENGTH = 16 * 1024;
    // record header + maximum TLS 1.2 ciphertext expansion
    static final int MAX_ENCRYPTED_PACKET_LENGTH = 5 + MAX_PLAINTEXT_LENGTH + 2048;
    private static final int RECORD_OVERHEAD = MAX_ENCRYPTED_PACKET_LENGTH - MAX_PLAINTEXT_LENGTH;

    private static final List<String> SUPPORTED_PROTOCOLS = List.of("TLSv1.2", "TLSv1.3");

    private final OpenSslContext serverContext;
    private final OpenSslContext clientContext;
    // freed with the engine; Arena.ofShared needs -H:+SharedArenaSupport in native executables
    private final MemorySegment buffer = Arena.ofAuto().allocate(MAX_ENCRYPTED_PACKET_LENGTH);
    private MemorySegment ssl;
    private MemorySegment networkBio;
    private final OpenSslSession session;

    private boolean clientMode;
    private String[] enabledProtocols = SUPPORTED_PROTOCOLS.toArray(String[]::new);
    private String[] enabledCipherSuites;
    private String endpointIdentificationAlgorithm;
    private String[] applicationProtocols = new String[0];
    private BiFunction<SSLEngine, List<String>, String> applicationProtocolSelector;
    private boolean needClientAuth;
    private boolean wantClientAuth;
    private boolean sessionCreation = true;

    private boolean started;
    private boolean opensslHandshakeDone;
    private boolean handshakeFinished;
    private boolean inboundDone;
    private boolean outboundDone;
    private boolean shutdownSent;
    private boolean freed;
    private SSLException failure;
    private String negotiatedProtocol = "NONE";
    private String negotiatedCipherSuite = "SSL_NULL_WITH_NULL_NULL";
    private String negotiatedApplicationProtocol;
    private X509Certificate[] peerCertificates;
    private Exception verifyFailure;

    OpenSslEngine(OpenSslContext context, String peerHost, int peerPort) {
        this(context, context, peerHost, peerPort);
    }

    OpenSslEngine(OpenSslContext serverContext, OpenSslContext clientContext, String peerHost, int peerPort) {
        super(peerHost, peerPort);
        this.serverContext = serverContext;
        this.clientContext = clientContext;
        this.session = new OpenSslSession(this);
    }

    private OpenSslContext context() {
        return clientMode ? clientContext : serverContext;
    }

    // --- handshake

    @Override
    public synchronized void beginHandshake() throws SSLException {
        checkFailure();
        if (started) {
            if (handshakeFinished) {
                throw new SSLException("Renegotiation is not supported");
            }
            return;
        }
        if (freed || outboundDone || inboundDone) {
            throw new SSLException("The engine is closed");
        }
        createSsl();
        started = true;
        doHandshake();
    }

    private void createSsl() throws SSLException {
        try {
            OpenSsl.clearError();
            ssl = (MemorySegment) Handles.SSL_new.invokeExact(context().ctx());
            if (ssl.equals(MemorySegment.NULL)) {
                throw new SSLException("SSL_new failed: " + OpenSsl.lastError());
            }
            OpenSslCallbacks.register(ssl, this);
            try (Arena local = Arena.ofConfined()) {
                MemorySegment internal = local.allocate(ValueLayout.ADDRESS);
                MemorySegment network = local.allocate(ValueLayout.ADDRESS);
                if ((int) Handles.BIO_new_bio_pair.invokeExact(internal, 0L, network, 0L) != 1) {
                    throw new SSLException("BIO_new_bio_pair failed: " + OpenSsl.lastError());
                }
                MemorySegment internalBio = internal.get(ValueLayout.ADDRESS, 0);
                networkBio = network.get(ValueLayout.ADDRESS, 0);
                // SSL_free releases the internal BIO
                Handles.SSL_set_bio.invokeExact(ssl, internalBio, internalBio);
            }
            applyCipherSuitesAndProtocols();
            int verifyMode;
            if (clientMode) {
                verifyMode = OpenSsl.SSL_VERIFY_PEER;
            } else if (needClientAuth) {
                verifyMode = OpenSsl.SSL_VERIFY_PEER | OpenSsl.SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            } else {
                verifyMode = wantClientAuth ? OpenSsl.SSL_VERIFY_PEER : OpenSsl.SSL_VERIFY_NONE;
            }
            Handles.SSL_set_verify.invokeExact(ssl, verifyMode, MemorySegment.NULL);
            if (clientMode && applicationProtocols.length > 0) {
                byte[] wire = encodeProtocols(applicationProtocols);
                try (Arena local = Arena.ofConfined()) {
                    if ((int) Handles.SSL_set_alpn_protos.invokeExact(ssl,
                            local.allocateFrom(ValueLayout.JAVA_BYTE, wire), wire.length) != 0) {
                        throw new SSLException("Cannot set the ALPN protocols: " + OpenSsl.lastError());
                    }
                }
            }
            if (clientMode) {
                String host = getPeerHost();
                if (host != null && !host.isEmpty() && !isIpLiteral(host)) {
                    try (Arena local = Arena.ofConfined()) {
                        long rc = (long) Handles.SSL_ctrl.invokeExact(ssl, OpenSsl.SSL_CTRL_SET_TLSEXT_HOSTNAME,
                                (long) OpenSsl.TLSEXT_NAMETYPE_host_name, local.allocateFrom(host));
                        if (rc != 1) {
                            throw new SSLException("Cannot set the SNI host name: " + OpenSsl.lastError());
                        }
                    }
                }
                Handles.SSL_set_connect_state.invokeExact(ssl);
            } else {
                Handles.SSL_set_accept_state.invokeExact(ssl);
            }
        } catch (SSLException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new SSLException(t);
        }
    }

    private void applyCipherSuitesAndProtocols() throws Throwable {
        List<String> enabled = Arrays.asList(enabledProtocols);
        boolean tls12 = enabled.contains("TLSv1.2");
        boolean tls13 = enabled.contains("TLSv1.3");
        if (enabledCipherSuites != null) {
            List<OpenSslCiphers.Suite> suites = new ArrayList<>();
            for (String name : enabledCipherSuites) {
                OpenSslCiphers.Suite suite = OpenSslCiphers.find(name);
                if (suite != null) {
                    suites.add(suite);
                }
            }
            List<String> suites12 = OpenSslCiphers.openSslNames(suites, false);
            List<String> suites13 = OpenSslCiphers.openSslNames(suites, true);
            tls12 &= !suites12.isEmpty();
            tls13 &= !suites13.isEmpty();
            try (Arena local = Arena.ofConfined()) {
                if ((int) Handles.SSL_set_ciphersuites.invokeExact(ssl,
                        local.allocateFrom(String.join(":", suites13))) != 1) {
                    throw new SSLException("Cannot set the TLS 1.3 cipher suites: " + OpenSsl.lastError());
                }
                if (!suites12.isEmpty() && (int) Handles.SSL_set_cipher_list.invokeExact(ssl,
                        local.allocateFrom(String.join(":", suites12))) != 1) {
                    throw new SSLException("Cannot set the cipher suites: " + OpenSsl.lastError());
                }
            }
        }
        if (!tls12 && !tls13) {
            throw new SSLHandshakeException("No enabled protocol has an enabled cipher suite");
        }
        int min = tls12 ? OpenSsl.TLS1_2_VERSION : OpenSsl.TLS1_3_VERSION;
        int max = tls13 ? OpenSsl.TLS1_3_VERSION : OpenSsl.TLS1_2_VERSION;
        if ((long) Handles.SSL_ctrl.invokeExact(ssl, OpenSsl.SSL_CTRL_SET_MIN_PROTO_VERSION, (long) min,
                MemorySegment.NULL) != 1
                || (long) Handles.SSL_ctrl.invokeExact(ssl, OpenSsl.SSL_CTRL_SET_MAX_PROTO_VERSION, (long) max,
                        MemorySegment.NULL) != 1) {
            throw new SSLException("Cannot set the protocol versions: " + OpenSsl.lastError());
        }
    }

    private void doHandshake() throws SSLException {
        if (opensslHandshakeDone) {
            return;
        }
        try {
            OpenSsl.clearError();
            int rc = (int) Handles.SSL_do_handshake.invokeExact(ssl);
            if (rc == 1) {
                opensslHandshakeDone = true;
                negotiatedProtocol = queryProtocol();
                negotiatedCipherSuite = queryCipherSuite();
                negotiatedApplicationProtocol = querySelectedApplicationProtocol();
                if (peerCertificates == null) {
                    peerCertificates = queryPeerCertificates();
                }
                return;
            }
            int error = (int) Handles.SSL_get_error.invokeExact(ssl, rc);
            if (error == OpenSsl.SSL_ERROR_WANT_READ || error == OpenSsl.SSL_ERROR_WANT_WRITE) {
                return;
            }
            String message = OpenSsl.lastError();
            SSLHandshakeException exception = new SSLHandshakeException(
                    "TLS handshake failed: " + (message == null ? "SSL error " + error : message));
            if (verifyFailure != null) {
                exception.initCause(verifyFailure);
            }
            fail(exception);
        } catch (SSLException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new SSLException(t);
        }
    }

    private void fail(SSLException e) throws SSLException {
        failure = e;
        inboundDone = true;
        throw e;
    }

    private void checkFailure() throws SSLException {
        if (failure != null) {
            throw failure;
        }
    }

    @Override
    public synchronized HandshakeStatus getHandshakeStatus() {
        if (!started || freed) {
            return HandshakeStatus.NOT_HANDSHAKING;
        }
        long pending = networkPending();
        if (!handshakeFinished) {
            if (pending > 0) {
                return HandshakeStatus.NEED_WRAP;
            }
            if (failure != null) {
                return HandshakeStatus.NOT_HANDSHAKING;
            }
            return opensslHandshakeDone ? HandshakeStatus.NOT_HANDSHAKING : HandshakeStatus.NEED_UNWRAP;
        }
        if (outboundDone && pending > 0) {
            return HandshakeStatus.NEED_WRAP;
        }
        if (outboundDone && !inboundDone) {
            return HandshakeStatus.NEED_UNWRAP;
        }
        return HandshakeStatus.NOT_HANDSHAKING;
    }

    /**
     * The status to report at the end of a {@code wrap} or {@code unwrap}, including {@code FINISHED} exactly once.
     */
    private HandshakeStatus resultHandshakeStatus() {
        if (!handshakeFinished && opensslHandshakeDone && networkPending() == 0) {
            handshakeFinished = true;
            return HandshakeStatus.FINISHED;
        }
        return getHandshakeStatus();
    }

    @Override
    public Runnable getDelegatedTask() {
        return null;
    }

    // --- data

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst) throws SSLException {
        checkBuffers(srcs, offset, length);
        if (dst.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }
        if (freed) {
            return new SSLEngineResult(Status.CLOSED, HandshakeStatus.NOT_HANDSHAKING, 0, 0);
        }
        if (!started && failure == null && !outboundDone) {
            beginHandshake();
        }
        if (outboundDone && started && !shutdownSent) {
            sendShutdown();
        }
        if (networkPending() > 0) {
            if (!dst.hasRemaining()) {
                return new SSLEngineResult(Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
            }
            int produced = readNetwork(dst);
            return result(outboundDone ? Status.CLOSED : Status.OK, 0, produced);
        }
        if (failure != null) {
            freeIfDone();
            throw failure;
        }
        if (outboundDone) {
            freeIfDone();
            return new SSLEngineResult(Status.CLOSED, getHandshakeStatus(), 0, 0);
        }
        if (!opensslHandshakeDone) {
            doHandshake();
            int produced = networkPending() > 0 && dst.hasRemaining() ? readNetwork(dst) : 0;
            return result(Status.OK, 0, produced);
        }
        // one record of application data
        ByteBuffer src = firstWithRemaining(srcs, offset, length);
        if (src == null) {
            return result(Status.OK, 0, 0);
        }
        int chunk = Math.min(src.remaining(), MAX_PLAINTEXT_LENGTH);
        if (dst.remaining() < chunk + RECORD_OVERHEAD) {
            return new SSLEngineResult(Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
        }
        int written = writePlaintext(src, chunk);
        int produced = readNetwork(dst);
        return result(Status.OK, written, produced);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
            throws SSLException {
        if (src == null) {
            throw new IllegalArgumentException("src is null");
        }
        checkBuffers(dsts, offset, length);
        int capacity = 0;
        for (int i = offset; i < offset + length; i++) {
            if (dsts[i].isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
            capacity += dsts[i].remaining();
        }
        checkFailure();
        if (freed || inboundDone) {
            freeIfDone();
            return new SSLEngineResult(Status.CLOSED, getHandshakeStatus(), 0, 0);
        }
        if (!started) {
            beginHandshake();
        }
        int recordLength = recordLength(src);
        if (recordLength < 0) {
            return new SSLEngineResult(Status.BUFFER_UNDERFLOW, getHandshakeStatus(), 0, 0);
        }
        if (opensslHandshakeDone && capacity < Math.min(recordLength - 5, MAX_PLAINTEXT_LENGTH)) {
            return new SSLEngineResult(Status.BUFFER_OVERFLOW, getHandshakeStatus(), 0, 0);
        }
        int consumed = writeNetwork(src, recordLength);
        if (!opensslHandshakeDone) {
            doHandshake();
            if (!opensslHandshakeDone) {
                return result(Status.OK, consumed, 0);
            }
        }
        int produced = 0;
        int index = offset;
        while (index < offset + length) {
            ByteBuffer dst = dsts[index];
            if (!dst.hasRemaining()) {
                index++;
                continue;
            }
            int read = readPlaintext(dst);
            if (read <= 0) {
                break;
            }
            produced += read;
        }
        if (inboundDone) {
            return result(Status.CLOSED, consumed, produced);
        }
        return result(Status.OK, consumed, produced);
    }

    private SSLEngineResult result(Status status, int consumed, int produced) {
        HandshakeStatus handshakeStatus = resultHandshakeStatus();
        freeIfDone();
        return new SSLEngineResult(status, handshakeStatus, consumed, produced);
    }

    private int writePlaintext(ByteBuffer src, int length) throws SSLException {
        MemorySegment.copy(MemorySegment.ofBuffer(src), 0, buffer, 0, length);
        try {
            OpenSsl.clearError();
            int rc = (int) Handles.SSL_write.invokeExact(ssl, buffer, length);
            if (rc <= 0) {
                int error = (int) Handles.SSL_get_error.invokeExact(ssl, rc);
                throw new SSLException("SSL_write failed (" + error + "): " + OpenSsl.lastError());
            }
            src.position(src.position() + rc);
            return rc;
        } catch (SSLException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new SSLException(t);
        }
    }

    private int readPlaintext(ByteBuffer dst) throws SSLException {
        int max = Math.min(dst.remaining(), (int) buffer.byteSize());
        try {
            OpenSsl.clearError();
            int rc = (int) Handles.SSL_read.invokeExact(ssl, buffer, max);
            if (rc > 0) {
                MemorySegment.copy(buffer, 0, MemorySegment.ofBuffer(dst), 0, rc);
                dst.position(dst.position() + rc);
                return rc;
            }
            int error = (int) Handles.SSL_get_error.invokeExact(ssl, rc);
            switch (error) {
                case OpenSsl.SSL_ERROR_WANT_READ, OpenSsl.SSL_ERROR_WANT_WRITE -> {
                    return 0;
                }
                case OpenSsl.SSL_ERROR_ZERO_RETURN -> {
                    inboundDone = true;
                    return 0;
                }
                default -> {
                    String message = OpenSsl.lastError();
                    fail(new SSLException("SSL_read failed (" + error + "): " + message));
                    return 0;
                }
            }
        } catch (SSLException | RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new SSLException(t);
        }
    }

    /**
     * The length of the TLS record at the position of {@code src}, header included,
     * or {@code -1} when the record is not complete yet.
     */
    private static int recordLength(ByteBuffer src) throws SSLException {
        if (src.remaining() < 5) {
            return -1;
        }
        int position = src.position();
        int length = 5 + (((src.get(position + 3) & 0xff) << 8) | (src.get(position + 4) & 0xff));
        if (length > MAX_ENCRYPTED_PACKET_LENGTH) {
            throw new SSLException("TLS record too long: " + length);
        }
        return src.remaining() < length ? -1 : length;
    }

    private int writeNetwork(ByteBuffer src, int length) throws SSLException {
        MemorySegment.copy(MemorySegment.ofBuffer(src), 0, buffer, 0, length);
        try {
            int rc = (int) Handles.BIO_write.invokeExact(networkBio, buffer, length);
            if (rc != length) {
                throw new SSLException("Cannot pass a TLS record to OpenSSL: BIO_write returned " + rc);
            }
            src.position(src.position() + rc);
            return rc;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new SSLException(t);
        }
    }

    private int readNetwork(ByteBuffer dst) throws SSLException {
        int length = (int) Math.min(Math.min(networkPending(), dst.remaining()), buffer.byteSize());
        if (length == 0) {
            return 0;
        }
        try {
            int rc = (int) Handles.BIO_read.invokeExact(networkBio, buffer, length);
            if (rc <= 0) {
                return 0;
            }
            MemorySegment.copy(buffer, 0, MemorySegment.ofBuffer(dst), 0, rc);
            dst.position(dst.position() + rc);
            return rc;
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new SSLException(t);
        }
    }

    private long networkPending() {
        if (networkBio == null || freed) {
            return 0;
        }
        try {
            return (long) Handles.BIO_ctrl_pending.invokeExact(networkBio);
        } catch (Throwable t) {
            throw OpenSsl.rethrow(t);
        }
    }

    // --- closing

    @Override
    public synchronized void closeInbound() throws SSLException {
        inboundDone = true;
        freeIfDone();
    }

    @Override
    public synchronized boolean isInboundDone() {
        return inboundDone;
    }

    @Override
    public synchronized void closeOutbound() {
        if (outboundDone) {
            return;
        }
        outboundDone = true;
        if (started && opensslHandshakeDone && !freed) {
            sendShutdown();
        }
        freeIfDone();
    }

    private void sendShutdown() {
        shutdownSent = true;
        if (!opensslHandshakeDone) {
            return;
        }
        try {
            OpenSsl.clearError();
            int rc = (int) Handles.SSL_shutdown.invokeExact(ssl);
            if (rc < 0) {
                OpenSsl.clearError();
            }
        } catch (Throwable t) {
            throw OpenSsl.rethrow(t);
        }
    }

    @Override
    public synchronized boolean isOutboundDone() {
        return outboundDone && networkPending() == 0;
    }

    private void freeIfDone() {
        if (freed || !inboundDone || !outboundDone || networkPending() > 0) {
            return;
        }
        free();
    }

    private void free() {
        freed = true;
        try {
            if (ssl != null) {
                OpenSslCallbacks.unregister(ssl);
                Handles.SSL_free.invokeExact(ssl);
            }
            if (networkBio != null) {
                int ignored = (int) Handles.BIO_free.invokeExact(networkBio);
            }
        } catch (Throwable t) {
            throw OpenSsl.rethrow(t);
        }
    }

    // --- session information used by OpenSslSession

    synchronized String protocol() {
        return negotiatedProtocol;
    }

    synchronized String cipherSuite() {
        return negotiatedCipherSuite;
    }

    private String queryProtocol() {
        try {
            MemorySegment version = (MemorySegment) Handles.SSL_get_version.invokeExact(ssl);
            return version.reinterpret(64).getString(0, StandardCharsets.US_ASCII);
        } catch (Throwable t) {
            throw OpenSsl.rethrow(t);
        }
    }

    private String queryCipherSuite() {
        try {
            MemorySegment cipher = (MemorySegment) Handles.SSL_get_current_cipher.invokeExact(ssl);
            if (cipher.equals(MemorySegment.NULL)) {
                return "SSL_NULL_WITH_NULL_NULL";
            }
            MemorySegment name = (MemorySegment) Handles.SSL_CIPHER_standard_name.invokeExact(cipher);
            return name.equals(MemorySegment.NULL) ? "SSL_NULL_WITH_NULL_NULL"
                    : name.reinterpret(128).getString(0, StandardCharsets.US_ASCII);
        } catch (Throwable t) {
            throw OpenSsl.rethrow(t);
        }
    }

    // --- configuration

    @Override
    public String[] getSupportedCipherSuites() {
        return OpenSslCiphers.supported();
    }

    @Override
    public synchronized String[] getEnabledCipherSuites() {
        return enabledCipherSuites == null ? OpenSslCiphers.defaults() : enabledCipherSuites.clone();
    }

    @Override
    public synchronized void setEnabledCipherSuites(String[] suites) {
        List<String> accepted = new ArrayList<>();
        for (String suite : suites) {
            if (OpenSslCiphers.find(suite) != null) {
                accepted.add(suite);
            } else if (!suite.endsWith("_SCSV")) {
                throw new IllegalArgumentException("Unsupported cipher suite: " + suite);
            }
        }
        enabledCipherSuites = accepted.toArray(String[]::new);
    }

    @Override
    public synchronized SSLParameters getSSLParameters() {
        SSLParameters parameters = super.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm(endpointIdentificationAlgorithm);
        parameters.setApplicationProtocols(applicationProtocols.clone());
        return parameters;
    }

    @Override
    public synchronized void setSSLParameters(SSLParameters parameters) {
        super.setSSLParameters(parameters);
        endpointIdentificationAlgorithm = parameters.getEndpointIdentificationAlgorithm();
        applicationProtocols = parameters.getApplicationProtocols().clone();
    }

    @Override
    public synchronized SSLSession getHandshakeSession() {
        return started && !handshakeFinished && !freed ? session : null;
    }

    @Override
    public synchronized String getApplicationProtocol() {
        return opensslHandshakeDone ? negotiatedApplicationProtocol : null;
    }

    @Override
    public synchronized String getHandshakeApplicationProtocol() {
        if (!started || handshakeFinished || freed) {
            return null;
        }
        String selected = querySelectedApplicationProtocol();
        return selected.isEmpty() ? null : selected;
    }

    @Override
    public synchronized void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> selector) {
        applicationProtocolSelector = selector;
    }

    @Override
    public synchronized BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return applicationProtocolSelector;
    }

    // --- callbacks, called on the thread running the handshake

    synchronized boolean verifyPeer(MemorySegment storeCtx) {
        try {
            MemorySegment leaf = (MemorySegment) Handles.X509_STORE_CTX_get0_cert.invokeExact(storeCtx);
            MemorySegment untrusted = (MemorySegment) Handles.X509_STORE_CTX_get0_untrusted.invokeExact(storeCtx);
            X509Certificate[] chain = OpenSslCertificates.chain(leaf, untrusted);
            if (chain.length == 0) {
                throw new CertificateException("The peer sent no certificate");
            }
            peerCertificates = chain;
            String authType = chain[0].getPublicKey().getAlgorithm();
            X509TrustManager trustManager = context().trustManager();
            if (trustManager instanceof X509ExtendedTrustManager extended) {
                if (clientMode) {
                    extended.checkServerTrusted(chain, authType, this);
                } else {
                    extended.checkClientTrusted(chain, authType, this);
                }
            } else if (clientMode) {
                trustManager.checkServerTrusted(chain, authType);
            } else {
                trustManager.checkClientTrusted(chain, authType);
            }
            return true;
        } catch (Throwable t) {
            verifyFailure = t instanceof Exception e ? e : new CertificateException(t);
            return false;
        }
    }

    synchronized int selectApplicationProtocol(MemorySegment out, MemorySegment outLength, MemorySegment in) {
        List<String> offered = new ArrayList<>();
        List<Long> offsets = new ArrayList<>();
        long position = 0;
        while (position < in.byteSize()) {
            int length = Byte.toUnsignedInt(in.get(ValueLayout.JAVA_BYTE, position));
            offsets.add(position + 1);
            offered.add(new String(in.asSlice(position + 1, length).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.US_ASCII));
            position += 1 + length;
        }
        String chosen;
        if (applicationProtocolSelector != null) {
            chosen = applicationProtocolSelector.apply(this, List.copyOf(offered));
            if (chosen != null && chosen.isEmpty()) {
                return OpenSsl.SSL_TLSEXT_ERR_NOACK;
            }
        } else if (applicationProtocols.length == 0) {
            return OpenSsl.SSL_TLSEXT_ERR_NOACK;
        } else {
            chosen = null;
            for (String protocol : applicationProtocols) {
                if (offered.contains(protocol)) {
                    chosen = protocol;
                    break;
                }
            }
        }
        int index = chosen == null ? -1 : offered.indexOf(chosen);
        if (index < 0) {
            return OpenSsl.SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        out.set(ValueLayout.ADDRESS, 0, in.asSlice(offsets.get(index)));
        outLength.set(ValueLayout.JAVA_BYTE, 0, (byte) chosen.length());
        return OpenSsl.SSL_TLSEXT_ERR_OK;
    }

    private String querySelectedApplicationProtocol() {
        try (Arena local = Arena.ofConfined()) {
            MemorySegment data = local.allocate(ValueLayout.ADDRESS);
            MemorySegment length = local.allocate(ValueLayout.JAVA_INT);
            Handles.SSL_get0_alpn_selected.invokeExact(ssl, data, length);
            int size = length.get(ValueLayout.JAVA_INT, 0);
            MemorySegment selected = data.get(ValueLayout.ADDRESS, 0);
            if (size == 0 || selected.equals(MemorySegment.NULL)) {
                return "";
            }
            return new String(selected.reinterpret(size).toArray(ValueLayout.JAVA_BYTE), StandardCharsets.US_ASCII);
        } catch (Throwable t) {
            throw OpenSsl.rethrow(t);
        }
    }

    private X509Certificate[] queryPeerCertificates() throws Throwable {
        MemorySegment leaf = (MemorySegment) Handles.SSL_get1_peer_certificate.invokeExact(ssl);
        if (leaf.equals(MemorySegment.NULL)) {
            return null;
        }
        try {
            MemorySegment stack = (MemorySegment) Handles.SSL_get_peer_cert_chain.invokeExact(ssl);
            return OpenSslCertificates.chain(leaf, stack);
        } finally {
            Handles.X509_free.invokeExact(leaf);
        }
    }

    synchronized X509Certificate[] peerCertificates() {
        return peerCertificates == null ? null : peerCertificates.clone();
    }

    synchronized X509Certificate[] localCertificates() {
        return context().chain();
    }

    private static byte[] encodeProtocols(String[] protocols) throws SSLException {
        java.io.ByteArrayOutputStream wire = new java.io.ByteArrayOutputStream();
        for (String protocol : protocols) {
            byte[] bytes = protocol.getBytes(StandardCharsets.US_ASCII);
            if (bytes.length == 0 || bytes.length > 255) {
                throw new SSLException("Invalid application protocol: " + protocol);
            }
            wire.write(bytes.length);
            wire.writeBytes(bytes);
        }
        return wire.toByteArray();
    }

    @Override
    public String[] getSupportedProtocols() {
        return SUPPORTED_PROTOCOLS.toArray(String[]::new);
    }

    @Override
    public synchronized String[] getEnabledProtocols() {
        return enabledProtocols.clone();
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols) {
        List<String> requested = Arrays.stream(protocols).filter(SUPPORTED_PROTOCOLS::contains).toList();
        if (requested.isEmpty()) {
            throw new IllegalArgumentException("None of " + Arrays.toString(protocols) + " is supported");
        }
        enabledProtocols = requested.toArray(String[]::new);
    }

    @Override
    public SSLSession getSession() {
        return session;
    }

    @Override
    public synchronized void setUseClientMode(boolean mode) {
        if (started) {
            throw new IllegalArgumentException("The handshake has started");
        }
        clientMode = mode;
    }

    @Override
    public synchronized boolean getUseClientMode() {
        return clientMode;
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need) {
        needClientAuth = need;
        wantClientAuth = false;
    }

    @Override
    public synchronized boolean getNeedClientAuth() {
        return needClientAuth;
    }

    @Override
    public synchronized void setWantClientAuth(boolean want) {
        wantClientAuth = want;
        needClientAuth = false;
    }

    @Override
    public synchronized boolean getWantClientAuth() {
        return wantClientAuth;
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag) {
        sessionCreation = flag;
    }

    @Override
    public synchronized boolean getEnableSessionCreation() {
        return sessionCreation;
    }

    private static ByteBuffer firstWithRemaining(ByteBuffer[] buffers, int offset, int length) {
        for (int i = offset; i < offset + length; i++) {
            if (buffers[i].hasRemaining()) {
                return buffers[i];
            }
        }
        return null;
    }

    private static void checkBuffers(ByteBuffer[] buffers, int offset, int length) {
        if (buffers == null) {
            throw new IllegalArgumentException("buffers is null");
        }
        if (offset < 0 || length < 0 || offset > buffers.length - length) {
            throw new IndexOutOfBoundsException();
        }
        for (int i = offset; i < offset + length; i++) {
            if (buffers[i] == null) {
                throw new IllegalArgumentException("null buffer at index " + i);
            }
        }
    }

    private static boolean isIpLiteral(String host) {
        return host.indexOf(':') >= 0 || host.chars().allMatch(c -> c == '.' || Character.isDigit(c));
    }
}
