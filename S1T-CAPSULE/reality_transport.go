package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
)

// generateRealityKeyPair creates a REALITY X25519 key pair in the same
// unpadded Base64URL format accepted by common REALITY clients.
func generateRealityKeyPair() (privateKey, publicKey string, err error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate X25519 key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func decodeRealityKey(encoded string, wantLen int) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("key is empty")
	}
	encodings := []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding}
	for _, enc := range encodings {
		b, err := enc.DecodeString(encoded)
		if err == nil && len(b) == wantLen {
			return b, nil
		}
	}
	return nil, fmt.Errorf("expected a Base64 key decoding to %d bytes", wantLen)
}

// normalizeRealityShortID maps a hex short ID to REALITY's fixed eight-byte key.
// Short IDs shorter than eight bytes are zero-padded on the right, as required
// by the wire representation.
func normalizeRealityShortID(value string) ([8]byte, error) {
	var out [8]byte
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "0x"))
	if len(value) < 2 || len(value) > 16 || len(value)%2 != 0 {
		return out, errors.New("short ID must be 2–16 hexadecimal characters (whole bytes)")
	}
	b, err := hex.DecodeString(value)
	if err != nil {
		return out, errors.New("short ID must contain hexadecimal characters only")
	}
	copy(out[:], b)
	return out, nil
}

func validateRealityKeyPair(privateEncoded, publicEncoded string) error {
	privBytes, err := decodeRealityKey(privateEncoded, 32)
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}
	pubBytes, err := decodeRealityKey(publicEncoded, 32)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return fmt.Errorf("parse X25519 private key: %w", err)
	}
	if subtle.ConstantTimeCompare(priv.PublicKey().Bytes(), pubBytes) != 1 {
		return errors.New("REALITY public key does not match the configured private key")
	}
	return nil
}

func makeRealityServerConfig(cfg Config) (*reality.Config, error) {
	if err := validateRealityKeyPair(cfg.RealityPrivateKey, cfg.RealityPublicKey); err != nil {
		return nil, err
	}
	privBytes, err := decodeRealityKey(cfg.RealityPrivateKey, 32)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("parse X25519 private key: %w", err)
	}
	shortID, err := normalizeRealityShortID(cfg.RealityShortID)
	if err != nil {
		return nil, err
	}
	rc := &reality.Config{
		Type:        "tcp",
		Dest:        cfg.RealityDest,
		ServerNames: map[string]bool{cfg.RealitySNI: true},
		PrivateKey:  priv.Bytes(),
		MaxTimeDiff: 2 * time.Minute,
		ShortIds:    map[[8]byte]bool{shortID: true},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
			return dialer.DialContext(ctx, network, address)
		},
	}
	// This is required when REALITY.Server is attached directly to a raw TCP
	// listener instead of using REALITY's convenience listener.
	reality.DetectPostHandshakeRecordsLens(rc)
	return rc, nil
}

func realityClientHelloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "chrome":
		// Pin a profile that explicitly offers both X25519MLKEM768 and
		// standalone X25519. The pinned XTLS/REALITY server rejects ClientHello
		// messages that omit the hybrid share; Auto can move between profiles
		// as uTLS changes, which made the wire behavior version-dependent.
		return utls.HelloChrome_133, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "random", "randomized":
		return utls.HelloRandomized, nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported REALITY ClientHello fingerprint %q (use chrome, firefox, edge, or randomized)", name)
	}
}

// clientHelloIDForLegacy uses uTLS for non-REALITY TLS transports as well. The
// certificate pin remains the trust anchor; browser profiles only affect the
// ClientHello and do not disable peer authentication.
func clientHelloIDForLegacy(name string) (utls.ClientHelloID, error) {
	id, err := realityClientHelloID(name)
	if err != nil {
		return utls.ClientHelloID{}, fmt.Errorf("unsupported TLS ClientHello profile: %w", err)
	}
	return id, nil
}

// utlsStandardConn exposes crypto/tls.ConnectionState to net/http. uTLS has
// its own ConnectionState type; without this adapter, net/http cannot reliably
// detect ALPN=h2 on DialTLSContext connections and may fall back to HTTP/1.1.
type utlsStandardConn struct{ *utls.UConn }

func (c *utlsStandardConn) ConnectionState() tls.ConnectionState {
	s := c.UConn.ConnectionState()
	return tls.ConnectionState{
		Version: s.Version, HandshakeComplete: s.HandshakeComplete, DidResume: s.DidResume,
		CipherSuite: s.CipherSuite, NegotiatedProtocol: s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual: s.NegotiatedProtocolIsMutual, ServerName: s.ServerName,
		PeerCertificates: s.PeerCertificates, VerifiedChains: s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps, OCSPResponse: s.OCSPResponse,
		TLSUnique: s.TLSUnique, ECHAccepted: s.ECHAccepted,
	}
}

func dialUTLSConnWithPin(raw net.Conn, pin []byte, serverName string, nextProtos []string, fingerprint string) (net.Conn, error) {
	if raw == nil {
		return nil, errors.New("nil raw connection")
	}
	if len(pin) != sha256.Size {
		_ = raw.Close()
		return nil, errors.New("Hub certificate pin must be a SHA-256 digest")
	}
	id, err := clientHelloIDForLegacy(fingerprint)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	verifyPin := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("Hub presented no certificate")
		}
		sum := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
			return errors.New("Hub TLS certificate fingerprint mismatch")
		}
		return nil
	}
	cfg := &utls.Config{
		ServerName: serverName, MinVersion: utls.VersionTLS13, NextProtos: append([]string(nil), nextProtos...),
		InsecureSkipVerify:    true, // the pinned DER fingerprint is verified below
		VerifyPeerCertificate: verifyPin,
	}
	conn := utls.UClient(raw, cfg, id)
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("uTLS handshake (%s profile): %w", fingerprint, err)
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		_ = raw.Close()
		return nil, errors.New("Hub presented no certificate")
	}
	sum := sha256.Sum256(state.PeerCertificates[0].Raw)
	if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
		_ = raw.Close()
		return nil, errors.New("Hub TLS certificate fingerprint mismatch")
	}
	if len(nextProtos) > 0 && state.NegotiatedProtocol != nextProtos[0] {
		_ = raw.Close()
		return nil, fmt.Errorf("Hub did not negotiate required ALPN %q (got %q)", nextProtos[0], state.NegotiatedProtocol)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return &utlsStandardConn{UConn: conn}, nil
}

// hkdfSHA256 implements HKDF-Extract + HKDF-Expand (RFC 5869) for a single
// 32-byte REALITY authentication key, avoiding dependency on a specific HKDF API.
func hkdfSHA256(secret, salt, info []byte) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write(info)
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

// realityAuthKeyShare follows the pinned XTLS/REALITY server's preference:
// standalone X25519 first; the hybrid share's X25519 component is fallback.
func realityAuthKeyShare(plainX25519, hybridX25519 *ecdh.PrivateKey) *ecdh.PrivateKey {
	if plainX25519 != nil {
		return plainX25519
	}
	return hybridX25519
}

func dialRealityClientConn(raw net.Conn, cfg Config) (net.Conn, error) {
	publicBytes, err := decodeRealityKey(cfg.RealityPublicKey, 32)
	if err != nil {
		return nil, fmt.Errorf("decode REALITY public key: %w", err)
	}
	serverPublic, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, fmt.Errorf("parse REALITY public key: %w", err)
	}
	shortID, err := normalizeRealityShortID(cfg.RealityShortID)
	if err != nil {
		return nil, err
	}
	fingerprint, err := realityClientHelloID(cfg.RealityFingerprint)
	if err != nil {
		return nil, err
	}

	var authKey []byte
	var realityVerified bool
	verifyPeer := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("REALITY peer returned no certificate")
		}
		cert, parseErr := x509.ParseCertificate(rawCerts[0])
		if parseErr != nil {
			return fmt.Errorf("parse peer certificate: %w", parseErr)
		}
		if pub, ok := cert.PublicKey.(ed25519.PublicKey); ok && len(authKey) == 32 {
			mac := hmac.New(sha512.New, authKey)
			_, _ = mac.Write(pub)
			want := mac.Sum(nil)
			if len(cert.Signature) == len(want) && subtle.ConstantTimeCompare(cert.Signature, want) == 1 {
				realityVerified = true
				return nil
			}
		}

		// A valid certificate from the cover website is an expected fallback
		// response, not proof that the peer is our Hub. Accept it only long
		// enough to finish the handshake; the caller then closes the stream
		// without sending the ShahTunnel token or tunnel preface.
		intermediates := x509.NewCertPool()
		for _, der := range rawCerts[1:] {
			if intermediate, e := x509.ParseCertificate(der); e == nil {
				intermediates.AddCert(intermediate)
			}
		}
		_, verifyErr := cert.Verify(x509.VerifyOptions{DNSName: cfg.RealitySNI, Intermediates: intermediates})
		if verifyErr != nil {
			return fmt.Errorf("peer is neither an authenticated REALITY Hub nor a valid cover-site certificate: %w", verifyErr)
		}
		return nil
	}

	tlsCfg := &utls.Config{
		ServerName:             cfg.RealitySNI,
		MinVersion:             utls.VersionTLS13,
		InsecureSkipVerify:     true, // verification is performed above, including REALITY's auth signature
		SessionTicketsDisabled: true,
		VerifyPeerCertificate:  verifyPeer,
	}
	uConn := utls.UClient(raw, tlsCfg, fingerprint)
	_ = uConn.SetDeadline(time.Now().Add(12 * time.Second))
	if err = uConn.BuildHandshakeState(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("build uTLS ClientHello: %w", err)
	}
	hello := uConn.HandshakeState.Hello
	if hello == nil || len(hello.Random) != 32 || len(hello.Raw) < 71 {
		_ = raw.Close()
		return nil, errors.New("uTLS generated an incomplete TLS ClientHello")
	}
	// In current uTLS releases State13 is a value (not a pointer), so it
	// cannot be checked against nil. A missing TLS 1.3 key share is checked
	// below through the ECDHE key-share fields instead.
	// The pinned XTLS/REALITY server requires an X25519MLKEM768 hybrid
	// key share before it will even try REALITY authentication. It then uses
	// the standalone X25519 share when both are present. Check this explicitly
	// so an incompatible fingerprint fails locally with a useful message
	// instead of silently falling through to the cover-site path and showing EOF.
	keyShares := uConn.HandshakeState.State13.KeyShareKeys
	if keyShares.MlkemEcdhe == nil {
		_ = raw.Close()
		return nil, errors.New("REALITY requires the X25519MLKEM768 hybrid key share; use the chrome fingerprint")
	}
	if keyShares.Ecdhe == nil {
		_ = raw.Close()
		return nil, errors.New("REALITY Chrome profile did not create the standalone X25519 key share")
	}
	ecdhe := realityAuthKeyShare(keyShares.Ecdhe, keyShares.MlkemEcdhe)
	if ecdhe == nil {
		_ = raw.Close()
		return nil, errors.New("REALITY ClientHello did not create a usable TLS 1.3 key share")
	}

	// REALITY authenticates the ClientHello by encrypting the 16-byte metadata
	// (version, timestamp, short ID) into TLS 1.3's 32-byte compatibility session ID.
	// The authenticated marker is part of the TLS transcript, unlike an ad-hoc
	// extension or an HTTP-level secret.
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0], hello.SessionId[1], hello.SessionId[2], hello.SessionId[3] = 1, 7, 0, 0
	binary.BigEndian.PutUint32(hello.SessionId[4:8], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:16], shortID[:])

	shared, err := ecdhe.ECDH(serverPublic)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("derive REALITY shared key: %w", err)
	}
	authKey = hkdfSHA256(shared, hello.Random[:20], []byte("REALITY"))
	block, err := aes.NewCipher(authKey)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("initialize REALITY authenticator: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("initialize REALITY AEAD: %w", err)
	}
	// hello.Raw must contain a zeroed session-ID field as associated data.
	copy(hello.Raw[39:], make([]byte, 32))
	sealed := aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	if len(sealed) != 32 {
		_ = raw.Close()
		return nil, errors.New("REALITY ClientHello authenticator has an invalid size")
	}
	copy(hello.Raw[39:], hello.SessionId)

	if err = uConn.HandshakeContext(context.Background()); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("REALITY TLS 1.3 handshake: %w", err)
	}
	if !realityVerified {
		_ = uConn.Close()
		return nil, errors.New("cover-site certificate received; REALITY Hub authentication failed; tunnel token was not sent")
	}
	_ = uConn.SetDeadline(time.Time{})
	return uConn, nil
}

func connectAndRunAgentReality(cfg Config, channel int) error {
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	addr, err := realityAgentAddress(cfg)
	if err != nil {
		return fmt.Errorf("derive REALITY Hub address: %w", err)
	}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial REALITY Hub: %w", err)
	}
	conn, err := dialRealityClientConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err = writeFull(conn, []byte("RREV3 "+cfg.Token+"\n")); err != nil {
		_ = conn.Close()
		return fmt.Errorf("send authenticated tunnel preface: %w", err)
	}
	reader := bufio.NewReaderSize(conn, 64)
	reply, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("read REALITY Hub authentication response: %w", err)
	}
	if reply != "OK\n" {
		_ = conn.Close()
		return errors.New("REALITY Hub rejected the ShahTunnel token")
	}
	_ = conn.SetDeadline(time.Time{})
	return runAgentOverStream(&bufferedConn{Conn: conn, r: reader}, cfg, channel, transportReality)
}

// realityHandledFallback reports the documented error used by the pinned
// REALITY server package after it has handed an unauthenticated connection to
// its asynchronous cover-site proxy. Closing raw for this sentinel would tear
// down the fallback before the probe receives the real site's response.
func realityHandledFallback(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "processed invalid connection")
}

func (h *hubServer) serveRealityAgent(raw net.Conn, cfg *reality.Config) {
	// The REALITY package's wrapper intentionally ignores SetDeadline on its
	// MirrorConn. Set deadlines on the underlying TCP connection instead so a
	// silent peer cannot hold one of the bounded unauthenticated slots forever.
	_ = raw.SetDeadline(time.Now().Add(12 * time.Second))
	conn, err := reality.Server(context.Background(), raw, cfg)
	if err != nil {
		// The REALITY library owns the socket after successful fallback setup.
		// Do not close it here: its asynchronous copy loops must deliver the
		// cover site's certificate and response to the connecting probe.
		if realityHandledFallback(err) {
			logAuthFailure("unauthenticated connection handed to REALITY cover-site fallback")
			return
		}
		logAuthFailure("REALITY handshake failed (details suppressed)")
		_ = raw.Close()
		return
	}
	defer conn.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReaderSize(conn, 512)
	lineBytes, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		logAuthFailure("rejected oversized REALITY tunnel preface")
		return
	}
	if err != nil || authProtocol(string(lineBytes), h.cfg.Token) == "" {
		// Do not write an application-level banner or protocol error to a peer
		// that did not authenticate. In the normal probe path REALITY itself
		// forwards the handshake to the configured destination.
		logAuthFailure("rejected REALITY tunnel authentication")
		return
	}
	if err = writeFull(conn, []byte("OK\n")); err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	h.serveAuthorizedAgent(&bufferedConn{Conn: conn, r: reader}, transportReality)
}
