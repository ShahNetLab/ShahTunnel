package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestWebSocketUpgradeAndBidirectionalStream(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	defer serverRaw.Close()
	defer clientRaw.Close()
	_ = serverRaw.SetDeadline(time.Now().Add(5 * time.Second))
	_ = clientRaw.SetDeadline(time.Now().Add(5 * time.Second))

	serverResult := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		r := bufio.NewReaderSize(serverRaw, maxWebSocketHeaders)
		if err := acceptWebSocketUpgrade(serverRaw, r); err != nil {
			serverResult <- struct {
				conn net.Conn
				err  error
			}{err: err}
			return
		}
		serverResult <- struct {
			conn net.Conn
			err  error
		}{conn: &websocketConn{Conn: serverRaw, r: r}}
	}()
	clientConn, err := clientWebSocketUpgrade(clientRaw, "edge.example.net:443")
	if err != nil {
		t.Fatalf("client WebSocket upgrade: %v", err)
	}
	serverReady := <-serverResult
	if serverReady.err != nil {
		t.Fatalf("server WebSocket upgrade: %v", serverReady.err)
	}
	serverConn := serverReady.conn
	defer serverConn.Close()
	defer clientConn.Close()

	payload := bytes.Repeat([]byte("ShahTunnel-WebSocket-"), 3000)
	writeDone := make(chan error, 1)
	go func() {
		n, writeErr := clientConn.Write(payload)
		if writeErr == nil && n != len(payload) {
			writeErr = io.ErrShortWrite
		}
		writeDone <- writeErr
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(serverConn, got); err != nil {
		t.Fatalf("server read client payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("server received corrupted client payload")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client write: %v", err)
	}

	response := []byte("server-to-client acknowledgement")
	writeDone = make(chan error, 1)
	go func() {
		n, writeErr := serverConn.Write(response)
		if writeErr == nil && n != len(response) {
			writeErr = io.ErrShortWrite
		}
		writeDone <- writeErr
	}()
	got = make([]byte, len(response))
	if _, err := io.ReadFull(clientConn, got); err != nil {
		t.Fatalf("client read server payload: %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatal("client received corrupted server payload")
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("server write: %v", err)
	}
}

func TestTLSAgentTransportsInteroperateWithHub(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "hub.crt"), filepath.Join(certDir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	pin, err := normalizeFingerprint(fingerprint)
	if err != nil {
		t.Fatalf("normalize fingerprint: %v", err)
	}
	const token = "d9c4c0f6e1a04f9a91b8e9d4f6c7a8b0d9c4c0f6e1a04f9a91b8e9d4f6c7a8b0"

	for _, mode := range []string{transportTCP, transportWebSocket} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			h := &hubServer{cfg: Config{Role: "hub", Transport: transportAuto, Token: token}, sessions: make(map[*hubSession]struct{})}
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					h.serveAgent(conn, hubTLSConfig(cert))
				}
			}()

			d := net.Dialer{Timeout: 2 * time.Second}
			tlsConfig := agentTLSConfig(pin, "localhost")
			if mode == transportWebSocket {
				tlsConfig.NextProtos = []string{"http/1.1"}
			}
			tlsConn, err := tls.DialWithDialer(&d, "tcp", listener.Addr().String(), tlsConfig)
			if err != nil {
				t.Fatalf("TLS dial: %v", err)
			}
			var c net.Conn = tlsConn
			if mode == transportWebSocket {
				if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
					t.Fatalf("WebSocket TLS ALPN = %q; want http/1.1", got)
				}
				c, err = clientWebSocketUpgrade(tlsConn, listener.Addr().String())
				if err != nil {
					t.Fatalf("WebSocket upgrade: %v", err)
				}
			} else if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "" {
				t.Fatalf("raw TLS ALPN = %q; want empty for compatibility", got)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if err := writeFull(c, []byte("RREV3 "+token+"\n")); err != nil {
				t.Fatalf("send auth: %v", err)
			}
			reply, err := bufio.NewReaderSize(c, 64).ReadString('\n')
			if err != nil || reply != "OK\n" {
				t.Fatalf("auth response = %q, err=%v", reply, err)
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))

			w := newWire(c)
			defer w.close()
			var pingPayload [8]byte
			binary.BigEndian.PutUint64(pingPayload[:], uint64(time.Now().UnixNano()))
			if err := w.send(msgPing, 0, pingPayload[:]); err != nil {
				t.Fatalf("send tunnel PING: %v", err)
			}
			var hdr [9]byte
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				t.Fatalf("read tunnel PONG header: %v", err)
			}
			if hdr[0] != msgPong {
				t.Fatalf("reply frame type = %d; want PONG %d", hdr[0], msgPong)
			}
			n := binary.BigEndian.Uint32(hdr[5:9])
			if n != uint32(len(pingPayload)) {
				t.Fatalf("reply payload length = %d; want %d", n, len(pingPayload))
			}
			payload := make([]byte, n)
			if _, err := io.ReadFull(c, payload); err != nil {
				t.Fatalf("read tunnel PONG payload: %v", err)
			}
			if !bytes.Equal(payload, pingPayload[:]) {
				t.Fatalf("PONG payload = %x; want %x", payload, pingPayload)
			}
		})
	}
}

func TestTransportFallbackModesInteroperateWhenHubOnlyAllowsWebSocket(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "hub.crt"), filepath.Join(certDir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	pin, err := normalizeFingerprint(fingerprint)
	if err != nil {
		t.Fatalf("normalize fingerprint: %v", err)
	}
	const token = "a84c4e76e42a42e294cd89d41fcf47aea84c4e76e42a42e294cd89d41fcf47ae"

	for idx, mode := range []string{transportAuto, transportAdaptive} {
		t.Run(mode, func(t *testing.T) {
			channel := idx + 1
			agentPreferredTransport.Delete(channel)
			t.Cleanup(func() { agentPreferredTransport.Delete(channel) })

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			h := &hubServer{cfg: Config{Role: "hub", Transport: transportWebSocket, Token: token}, sessions: make(map[*hubSession]struct{})}
			acceptDone := make(chan struct{})
			go func() {
				defer close(acceptDone)
				for {
					conn, acceptErr := listener.Accept()
					if acceptErr != nil {
						return
					}
					go h.serveAgent(conn, hubTLSConfig(cert))
				}
			}()

			cfg := Config{
				Role:           "agent",
				Transport:      mode,
				HubAddr:        listener.Addr().String(),
				TLSServerName:  "localhost",
				Token:          token,
				TunnelChannels: 1,
				Ports:          []PortMapping{},
			}
			agentDone := make(chan error, 1)
			go func() { agentDone <- connectAndRunAgent(cfg, pin, channel) }()

			deadline := time.Now().Add(5 * time.Second)
			for h.sessionCount() == 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if h.sessionCount() == 0 {
				t.Fatalf("%s mode did not fall back to WebSocket/TLS when Hub only allowed WebSocket/TLS", mode)
			}
			if mode == transportAdaptive {
				for time.Now().Before(deadline) {
					if v, ok := agentPreferredTransport.Load(channel); ok && v == transportWebSocket {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if v, ok := agentPreferredTransport.Load(channel); !ok || v != transportWebSocket {
					t.Fatalf("adaptive mode did not remember WebSocket/TLS after successful authentication: value=%v present=%v", v, ok)
				}
			}

			h.mu.RLock()
			var active *hubSession
			for session := range h.sessions {
				active = session
				break
			}
			h.mu.RUnlock()
			if active == nil {
				t.Fatal("expected one active WebSocket-backed Hub session")
			}
			active.shutdown()
			select {
			case <-agentDone:
			case <-time.After(3 * time.Second):
				t.Fatalf("%s Agent routine did not exit after the test closed its tunnel lane", mode)
			}
			_ = listener.Close()
			select {
			case <-acceptDone:
			case <-time.After(2 * time.Second):
				t.Fatal("Hub accept loop did not stop")
			}
		})
	}
}

func listenAdjacentTCPPair(t *testing.T) (net.Listener, net.Listener) {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		base, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		h2Addr, err := adjacentPortAddress(base.Addr().String())
		if err != nil {
			_ = base.Close()
			continue
		}
		h2, err := net.Listen("tcp", h2Addr)
		if err != nil {
			_ = base.Close()
			continue
		}
		return base, h2
	}
	t.Fatal("could not reserve an adjacent TCP port pair after 100 attempts")
	return nil, nil
}

func listenAdjacentTCPTuple(t *testing.T) (net.Listener, net.Listener, net.Listener) {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		base, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		h2Addr, err := adjacentPortAddress(base.Addr().String())
		if err != nil {
			_ = base.Close()
			continue
		}
		h2, err := net.Listen("tcp", h2Addr)
		if err != nil {
			_ = base.Close()
			continue
		}
		h1Addr, err := secondAdjacentPortAddress(base.Addr().String())
		if err != nil {
			_ = base.Close()
			_ = h2.Close()
			continue
		}
		h1, err := net.Listen("tcp", h1Addr)
		if err != nil {
			_ = base.Close()
			_ = h2.Close()
			continue
		}
		return base, h2, h1
	}
	t.Fatal("could not reserve a control/H2/H1 TCP listener triple")
	return nil, nil, nil
}

func TestHTTP1CONNECTBidirectionalStream(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "hub.crt"), filepath.Join(certDir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	control, h2Listener, h1Listener := listenAdjacentTCPTuple(t)
	defer control.Close()
	_ = h2Listener.Close()
	const token = "bc6c7a7e0d9b747d69b9c4f7c3e9a8b7fbc6c7a7e0d9b747d69b9c4f7c3e9a8b7f"
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.Method != http.MethodConnect {
				http.Error(w, "HTTP/1.1 CONNECT required", http.StatusBadRequest)
				return
			}
			if !constantTimeTokenMatch(r.Header.Get(http2TokenHeader), token) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijack unavailable", http.StatusInternalServerError)
				return
			}
			conn, rw, err := hijacker.Hijack()
			if err != nil {
				return
			}
			if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				_ = conn.Close()
				return
			}
			if err = rw.Flush(); err != nil {
				_ = conn.Close()
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}},
		ReadHeaderTimeout: 3 * time.Second,
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.ServeTLS(h1Listener, "", "") }()
	t.Cleanup(func() { _ = server.Close(); <-done })
	cfg := Config{Role: "agent", Transport: transportHTTP1, HubAddr: control.Addr().String(), TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1}
	conn, err := dialHTTP1Connect(cfg)
	if err != nil {
		t.Fatalf("dial HTTP/1.1 CONNECT: %v", err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("ShahTunnel-H1-CONNECT-"), 4096)
	writeDone := make(chan error, 1)
	go func() {
		n, e := conn.Write(payload)
		if e == nil && n != len(payload) {
			e = io.ErrShortWrite
		}
		writeDone <- e
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read HTTP/1.1 CONNECT payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("HTTP/1.1 CONNECT payload differs from what was sent")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write HTTP/1.1 CONNECT payload: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/1.1 CONNECT write stalled")
	}
}

func TestHTTP2ConnectBidirectionalStream(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "hub.crt"), filepath.Join(certDir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}

	// Reserve an adjacent control/H2 pair, matching the production config rule.
	baseListener, h2Listener := listenAdjacentTCPPair(t)
	defer baseListener.Close()
	baseAddr := baseListener.Addr().String()

	const token = "c6c7a7e0d9b747d69b9c4f7c3e9a8b7fc6c7a7e0d9b747d69b9c4f7c3e9a8b7f"
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 || r.Method != http.MethodConnect {
				http.Error(w, "HTTP/2 CONNECT required", http.StatusBadRequest)
				return
			}
			if !constantTimeTokenMatch(r.Header.Get(http2TokenHeader), token) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = io.Copy(w, r.Body)
		}),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}},
		ReadHeaderTimeout: 3 * time.Second,
	}
	serveDone := make(chan struct{})
	go func() { defer close(serveDone); _ = server.ServeTLS(h2Listener, "", "") }()
	t.Cleanup(func() { _ = server.Close(); <-serveDone })

	cfg := Config{Role: "agent", Transport: transportHTTP2, HubAddr: baseAddr, TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1}
	conn, err := dialHTTP2Connect(cfg)
	if err != nil {
		t.Fatalf("dial HTTP/2 CONNECT: %v", err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("ShahTunnel-H2-CONNECT-"), 4096)
	writeDone := make(chan error, 1)
	go func() {
		n, e := conn.Write(payload)
		if e == nil && n != len(payload) {
			e = io.ErrShortWrite
		}
		writeDone <- e
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echoed HTTP/2 payload: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("HTTP/2 CONNECT payload differs from what was sent")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write HTTP/2 payload: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP/2 request-body write stalled")
	}
}

func TestAdaptiveFallbackAuthenticatesOverHTTP2Connect(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "hub.crt"), filepath.Join(certDir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	pin, err := normalizeFingerprint(fingerprint)
	if err != nil {
		t.Fatalf("normalize fingerprint: %v", err)
	}

	// Reserve a control port and its adjacent HTTP/2 CONNECT port.
	control, h2Listener := listenAdjacentTCPPair(t)
	controlAddr := control.Addr().String()

	const token = "d9c4c0f6e1a04f9a91b8e9d4f6c7a8b0d9c4c0f6e1a04f9a91b8e9d4f6c7a8b0"
	h := &hubServer{cfg: Config{Role: "hub", Transport: transportHTTP2, Token: token}, sessions: make(map[*hubSession]struct{})}
	var rawWG sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := control.Accept()
			if acceptErr != nil {
				return
			}
			rawWG.Add(1)
			go func(c net.Conn) { defer rawWG.Done(); h.serveAgent(c, hubTLSConfig(cert)) }(conn)
		}
	}()
	h2Server := &http.Server{
		Handler:           http.HandlerFunc(h.serveHTTP2Connect),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}},
		ReadHeaderTimeout: 3 * time.Second,
	}
	h2Done := make(chan struct{})
	go func() { defer close(h2Done); _ = h2Server.ServeTLS(h2Listener, "", "") }()
	t.Cleanup(func() {
		_ = h2Server.Close()
		_ = control.Close()
		<-h2Done
		<-acceptDone
		rawWG.Wait()
	})

	channel := 1
	agentPreferredTransport.Delete(channel)
	cfg := Config{Role: "agent", Transport: transportAdaptive, HubAddr: controlAddr, TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1, Ports: []PortMapping{}}
	agentDone := make(chan error, 1)
	go func() { agentDone <- connectAndRunAgent(cfg, pin, channel) }()
	deadline := time.Now().Add(8 * time.Second)
	for h.sessionCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.sessionCount() == 0 {
		t.Fatal("adaptive mode did not reach and authenticate over HTTP/2 CONNECT after TCP and WebSocket were rejected")
	}
	for time.Now().Before(deadline) {
		if got, ok := agentPreferredTransport.Load(channel); ok && got == transportHTTP2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got, ok := agentPreferredTransport.Load(channel); !ok || got != transportHTTP2 {
		t.Fatalf("adaptive mode did not remember HTTP/2 CONNECT after successful authentication: got=%v present=%v", got, ok)
	}

	h.mu.RLock()
	var active *hubSession
	for session := range h.sessions {
		active = session
		break
	}
	h.mu.RUnlock()
	if active == nil {
		t.Fatal("expected an authenticated HTTP/2-backed Hub session")
	}
	active.shutdown()
	select {
	case <-agentDone:
	case <-time.After(4 * time.Second):
		t.Fatal("Agent did not stop after the test shut down the H2 tunnel session")
	}
}

func TestAdaptiveFallbackAuthenticatesOverHTTP1Connect(t *testing.T) {
	testAgentFallbackOverHTTP1(t, transportAdaptive)
}

func TestHTTPConnectAutoFallsBackFromHTTP2ToHTTP1(t *testing.T) {
	testAgentFallbackOverHTTP1(t, transportHTTPConnectAuto)
}

func testAgentFallbackOverHTTP1(t *testing.T, agentMode string) {
	t.Helper()
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "hub.crt"), filepath.Join(certDir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load certificate: %v", err)
	}
	pin, err := normalizeFingerprint(fingerprint)
	if err != nil {
		t.Fatalf("normalize fingerprint: %v", err)
	}
	control, h2Listener, h1Listener := listenAdjacentTCPTuple(t)
	controlAddr := control.Addr().String()
	_ = h2Listener.Close() // intentionally unavailable: proves H2 -> H1 fallback
	const token = "d9c4c0f6e1a04f9a91b8e9d4f6c7a8b0d9c4c0f6e1a04f9a91b8e9d4f6c7a8b0"
	hubPolicy := transportHTTP1
	if agentMode == transportHTTPConnectAuto {
		hubPolicy = transportHTTPConnectAuto
	}
	h := &hubServer{cfg: Config{Role: "hub", Transport: hubPolicy, Token: token}, sessions: make(map[*hubSession]struct{})}
	var rawWG sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, acceptErr := control.Accept()
			if acceptErr != nil {
				return
			}
			rawWG.Add(1)
			go func(c net.Conn) { defer rawWG.Done(); h.serveAgent(c, hubTLSConfig(cert)) }(conn)
		}
	}()
	h1Server := &http.Server{Handler: http.HandlerFunc(h.serveHTTP1Connect), TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}, ReadHeaderTimeout: 3 * time.Second}
	h1Done := make(chan struct{})
	go func() { defer close(h1Done); _ = h1Server.ServeTLS(h1Listener, "", "") }()
	t.Cleanup(func() { _ = h1Server.Close(); _ = control.Close(); <-h1Done; <-acceptDone; rawWG.Wait() })
	channel := 1
	agentPreferredTransport.Delete(channel)
	cfg := Config{Role: "agent", Transport: agentMode, HubAddr: controlAddr, TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1, Ports: []PortMapping{}}
	agentDone := make(chan error, 1)
	go func() { agentDone <- connectAndRunAgent(cfg, pin, channel) }()
	deadline := time.Now().Add(8 * time.Second)
	for h.sessionCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.sessionCount() == 0 {
		t.Fatalf("%s did not authenticate over HTTP/1.1 CONNECT after previous paths failed", agentMode)
	}
	if agentMode == transportAdaptive {
		for time.Now().Before(deadline) {
			if got, ok := agentPreferredTransport.Load(channel); ok && got == transportHTTP1 {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if got, ok := agentPreferredTransport.Load(channel); !ok || got != transportHTTP1 {
			t.Fatalf("adaptive mode did not remember HTTP/1.1 CONNECT: got=%v present=%v", got, ok)
		}
	}
	h.mu.RLock()
	var active *hubSession
	for session := range h.sessions {
		active = session
		break
	}
	h.mu.RUnlock()
	if active == nil {
		t.Fatal("expected an authenticated HTTP/1.1-backed Hub session")
	}
	active.shutdown()
	select {
	case <-agentDone:
	case <-time.After(4 * time.Second):
		t.Fatalf("Agent did not stop after the test shut down the HTTP/1.1 tunnel session (%s)", agentMode)
	}
}

func TestTransportConfigDefaultsAndPolicy(t *testing.T) {
	if got := normalizeConfig(Config{Role: "hub"}).Transport; got != transportAuto {
		t.Fatalf("legacy Hub transport = %q; want %q", got, transportAuto)
	}
	if got := normalizeConfig(Config{Role: "agent"}).Transport; got != transportAuto {
		t.Fatalf("legacy Agent transport = %q; want %q", got, transportAuto)
	}
	if !transportAllowed(transportAuto, transportWebSocket) || transportAllowed(transportTCP, transportWebSocket) || !transportAllowed(transportWebSocket, transportWebSocket) {
		t.Fatal("transport allow policy does not enforce expected modes")
	}
	if !validTransportMode(transportAdaptive) || !transportAllowed(transportAdaptive, transportTCP) || !transportAllowed(transportAdaptive, transportWebSocket) {
		t.Fatal("adaptive mode must allow both implemented transports")
	}
	if !validTransportMode(transportHTTP2) || !transportAllowed(transportAdaptive, transportHTTP2) || !transportAllowed(transportHTTP2, transportHTTP2) {
		t.Fatal("HTTP/2 CONNECT must be a real, selectable transport")
	}
	if !validTransportMode(transportHTTP1) || !transportAllowed(transportAdaptive, transportHTTP1) || !transportAllowed(transportHTTP1, transportHTTP1) {
		t.Fatal("HTTP/1.1 CONNECT must be a real, selectable transport")
	}
	if !validTransportMode(transportHTTPConnectAuto) || !transportAllowed(transportHTTPConnectAuto, transportHTTP2) || !transportAllowed(transportHTTPConnectAuto, transportHTTP1) {
		t.Fatal("HTTP CONNECT fallback must allow HTTP/2 and HTTP/1.1 only")
	}
	if transportAllowed(transportHTTPConnectAuto, transportTCP) || transportAllowed(transportHTTPConnectAuto, transportWebSocket) {
		t.Fatal("HTTP CONNECT fallback must not silently allow native TLS/WebSocket transports")
	}
	for _, unsupported := range []string{"unsupported_legacy_transport", "not-a-transport"} {
		if isAdaptiveTransport(unsupported) {
			t.Fatalf("unknown adaptive preference %q was accepted", unsupported)
		}
		if validTransportMode(unsupported) {
			t.Fatalf("unknown transport %q was accepted", unsupported)
		}
	}
}

func TestAdaptiveTransportCandidatesPreferLastSuccessfulPath(t *testing.T) {
	wantAll := []string{transportTCP, transportWebSocket, transportHTTP2, transportHTTP1}
	got := adaptiveTransportCandidates("")
	if !equalStrings(got, wantAll) {
		t.Fatalf("default adaptive candidates = %v; want %v", got, wantAll)
	}
	for _, preferred := range wantAll {
		if !isAdaptiveTransport(preferred) {
			t.Fatalf("implemented transport %q is not accepted as an adaptive preference", preferred)
		}
		got := adaptiveTransportCandidates(preferred)
		if len(got) != len(wantAll) || got[0] != preferred {
			t.Fatalf("preferred %q gives candidates %v", preferred, got)
		}
		seen := make(map[string]bool, len(got))
		for _, candidate := range got {
			if seen[candidate] {
				t.Fatalf("candidate %q duplicated in %v", candidate, got)
			}
			seen[candidate] = true
		}
		if len(seen) != len(wantAll) {
			t.Fatalf("preferred %q candidates miss a path: %v", preferred, got)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestNormalizeConfigUpgradesAgentToTwelveLanes(t *testing.T) {
	got := normalizeConfig(Config{Role: "agent", TunnelChannels: 4})
	if got.TunnelChannels != 12 {
		t.Fatalf("TunnelChannels = %d; want 12", got.TunnelChannels)
	}
}

func TestHubSelectsLeastLoadedLaneAndRotatesTies(t *testing.T) {
	mkSession := func(id uint64, active int) *hubSession {
		streams := make(map[uint32]*hubStream, active)
		for i := 0; i < active; i++ {
			streams[uint32(i+1)] = &hubStream{}
		}
		return &hubSession{id: id, streams: streams, wire: &wire{done: make(chan struct{})}}
	}
	busy := mkSession(1, 4)
	lessBusy := mkSession(2, 1)
	h := &hubServer{sessions: map[*hubSession]struct{}{busy: {}, lessBusy: {}}}
	if got := h.current(); got != lessBusy {
		t.Fatalf("least-loaded lane = %d; want %d", got.id, lessBusy.id)
	}

	a := mkSession(3, 1)
	b := mkSession(4, 1)
	h = &hubServer{sessions: map[*hubSession]struct{}{a: {}, b: {}}}
	first := h.current()
	second := h.current()
	if first == second {
		t.Fatalf("equal-load lanes were not rotated; both selections chose lane %d", first.id)
	}
}

func TestHubPrefersLowerRTTAmongEquallyLoadedLanes(t *testing.T) {
	mkSession := func(id uint64, rtt time.Duration) *hubSession {
		w := &wire{done: make(chan struct{})}
		w.rttNanos.Store(int64(rtt))
		return &hubSession{id: id, streams: make(map[uint32]*hubStream), wire: w}
	}
	slow := mkSession(1, 80*time.Millisecond)
	fast := mkSession(2, 12*time.Millisecond)
	h := &hubServer{sessions: map[*hubSession]struct{}{slow: {}, fast: {}}}
	for i := 0; i < 10; i++ {
		if got := h.current(); got != fast {
			t.Fatalf("selected lane %d with RTT %s; want low-RTT lane %d", got.id, got.wire.roundTripTime(), fast.id)
		}
	}
}

func TestHubKeepsRotatingWhenRTTIsNotYetKnown(t *testing.T) {
	mkSession := func(id uint64) *hubSession {
		return &hubSession{id: id, streams: make(map[uint32]*hubStream), wire: &wire{done: make(chan struct{})}}
	}
	a := mkSession(1)
	b := mkSession(2)
	h := &hubServer{sessions: map[*hubSession]struct{}{a: {}, b: {}}}
	first, second := h.current(), h.current()
	if first == second {
		t.Fatalf("unknown-RTT lanes did not rotate; both selections chose lane %d", first.id)
	}
}

func TestWireObservePongTracksRTTAndIgnoresMalformedPayload(t *testing.T) {
	w := &wire{}
	var payload [8]byte
	binary.BigEndian.PutUint64(payload[:], uint64(time.Now().Add(-40*time.Millisecond).UnixNano()))
	w.observePong(payload[:])
	got := w.roundTripTime()
	if got < 10*time.Millisecond || got > 2*time.Second {
		t.Fatalf("measured RTT = %s; want a positive short RTT", got)
	}
	before := w.roundTripTime()
	w.observePong([]byte{1, 2, 3})
	if after := w.roundTripTime(); after != before {
		t.Fatalf("malformed PONG changed RTT from %s to %s", before, after)
	}
}

func TestWireControlBurstDoesNotStarvePayload(t *testing.T) {
	writerConn, readerConn := net.Pipe()
	defer readerConn.Close()
	w := &wire{
		conn:     writerConn,
		controlQ: make(chan *wireRequest, 16),
		dataQ:    make(chan *wireRequest, 2),
		done:     make(chan struct{}),
	}
	writerDone := make(chan struct{})
	go func() {
		w.writeLoop()
		close(writerDone)
	}()

	for i := 0; i < 10; i++ {
		w.controlQ <- &wireRequest{typ: msgPing, id: uint32(i + 1), done: make(chan error, 1)}
	}
	w.dataQ <- &wireRequest{typ: msgData, id: 99, data: []byte("x"), done: make(chan error, 1)}

	types := make([]byte, 0, 11)
	for i := 0; i < 11; i++ {
		_ = readerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var header [9]byte
		if _, err := io.ReadFull(readerConn, header[:]); err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		length := binary.BigEndian.Uint32(header[5:9])
		if length > 0 {
			payload := make([]byte, int(length))
			if _, err := io.ReadFull(readerConn, payload); err != nil {
				t.Fatalf("read payload for frame %d: %v", i, err)
			}
		}
		types = append(types, header[0])
	}
	if types[controlBurstLimit] != msgData {
		t.Fatalf("frame after %d control frames = type %d; want payload type %d", controlBurstLimit, types[controlBurstLimit], msgData)
	}
	w.close()
	select {
	case <-writerDone:
	case <-time.After(time.Second):
		t.Fatal("wire writer did not stop after close")
	}
}

func writeTestFrame(conn net.Conn, typ byte, id uint32, data []byte) error {
	var header [9]byte
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:5], id)
	binary.BigEndian.PutUint32(header[5:9], uint32(len(data)))
	if err := writeFull(conn, header[:]); err != nil {
		return err
	}
	if len(data) != 0 {
		return writeFull(conn, data)
	}
	return nil
}

func readTestFrame(conn net.Conn) (byte, uint32, []byte, error) {
	var header [9]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, 0, nil, err
	}
	n := binary.BigEndian.Uint32(header[5:9])
	if n > maxFrame {
		return 0, 0, nil, io.ErrShortBuffer
	}
	data := make([]byte, int(n))
	if n > 0 {
		if _, err := io.ReadFull(conn, data); err != nil {
			return 0, 0, nil, err
		}
	}
	return header[0], binary.BigEndian.Uint32(header[1:5]), data, nil
}

func TestAgentAcceptsManyParallelOpens(t *testing.T) {
	const connectionCount = 128
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, connectionCount)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for i := 0; i < connectionCount; i++ {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	agentConn, peer := net.Pipe()
	session := newAgentSession(agentConn, map[string]string{"parallel-test": listener.Addr().String()})
	runDone := make(chan struct{})
	targetConns := make([]net.Conn, 0, connectionCount)
	go func() {
		session.run()
		close(runDone)
	}()
	defer func() {
		_ = peer.Close()
		select {
		case <-runDone:
		case <-time.After(2 * time.Second):
			t.Error("agent session did not stop")
		}
		_ = listener.Close()
		for _, c := range targetConns {
			_ = c.Close()
		}
		for {
			select {
			case c := <-accepted:
				_ = c.Close()
			default:
				return
			}
		}
	}()

	for id := 1; id <= connectionCount; id++ {
		if err := writeTestFrame(peer, msgOpen, uint32(id), []byte("parallel-test")); err != nil {
			t.Fatalf("send open %d: %v", id, err)
		}
	}
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	seen := make(map[uint32]bool, connectionCount)
	for i := 0; i < connectionCount; i++ {
		typ, id, data, err := readTestFrame(peer)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		if typ != msgOpenOK {
			t.Fatalf("stream %d received response type %d data %q; want msgOpenOK", id, typ, data)
		}
		seen[id] = true
	}
	if len(seen) != connectionCount {
		t.Fatalf("successful OPEN responses = %d; want %d", len(seen), connectionCount)
	}
	for i := 0; i < connectionCount; i++ {
		select {
		case c := <-accepted:
			targetConns = append(targetConns, c)
		case <-time.After(2 * time.Second):
			t.Fatalf("local target accepted fewer than %d parallel connections", connectionCount)
		}
	}
	select {
	case <-acceptDone:
	case <-time.After(time.Second):
		t.Fatal("target listener did not finish accepting connections")
	}
}

func TestQueuedPayloadBudgetAppliesBackpressure(t *testing.T) {
	if got := queuedPayloadBytes.Load(); got != 0 {
		t.Fatalf("queued payload budget starts at %d bytes; want 0", got)
	}
	for {
		select {
		case <-queuedPayloadChanged:
		default:
			goto drained
		}
	}

drained:
	queuedPayloadBytes.Store(maxQueuedPayloadBytes)
	done := make(chan struct{})
	finished := make(chan struct{})
	reserved := make(chan bool, 1)
	go func() {
		defer close(finished)
		reserved <- reserveQueuedPayloadWait(1024, done)
	}()
	select {
	case ok := <-reserved:
		t.Fatalf("reservation completed while budget was full (ok=%v)", ok)
	case <-time.After(30 * time.Millisecond):
	}
	releaseQueuedPayload(1024)
	select {
	case ok := <-reserved:
		if !ok {
			t.Fatal("reservation failed after capacity was released")
		}
	case <-time.After(time.Second):
		t.Fatal("reservation did not resume after capacity notification")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("reservation goroutine did not finish")
	}
	close(done)
	queuedPayloadBytes.Store(0)
	for {
		select {
		case <-queuedPayloadChanged:
		default:
			return
		}
	}
}

func TestShahTunnelLogoBitmap(t *testing.T) {
	if len(shahTunnelLogoPixels) != 22 {
		t.Fatalf("logo bitmap has %d rows; want 22", len(shahTunnelLogoPixels))
	}
	for y, row := range shahTunnelLogoPixels {
		if got := len(row); got != 22 {
			t.Errorf("logo row %d has width %d; want 22", y+1, got)
		}
		for x := 0; x < len(row); x++ {
			idx := logoPixelIndex(row[x])
			if idx < 0 || idx >= len(shahTunnelLogoPalette) {
				t.Errorf("logo pixel (%d,%d) references palette index %d", x, y, idx)
			}
		}
	}
}

func TestShahTunnelHeaderLayout(t *testing.T) {
	want := []string{
		"        +------------------------------------------+",
		"        |               SHAH TUNNEL                |",
		"        |          SECURE RELAY / TLS 1.3          |",
		"        +==========================================+",
		"        | CLIENT > TLS 1.3 > HUB > AGENT > TARGET  |",
		"        |      ENCRYPTED TRANSIT / TOKEN AUTH      |",
		"        |       EDGE > SECURE RELAY > TARGET       |",
		"        |     ZERO TRUST / MULTI-LANE / ONLINE     |",
		"        |     SESSION: ACTIVE / PRIVATE ROUTE      |",
		"        +------------------------------------------+",
		"  ╔══════════════════════════════════════════════════════════════╗",
		"  ║                         COMMAND DECK                         ║",
		"  ║       SECURE RELAY   •   TLS 1.3   •   ZERO TRUST            ║",
		"  ╚══════════════════════════════════════════════════════════════╝",
	}
	if len(shahTunnelHeaderArt) != len(want) {
		t.Fatalf("header has %d lines; want %d", len(shahTunnelHeaderArt), len(want))
	}
	for i := range want {
		if shahTunnelHeaderArt[i] != want[i] {
			t.Errorf("header line %d:\n got: %q\nwant: %q", i+1, shahTunnelHeaderArt[i], want[i])
		}
		width := 52
		if i >= 10 {
			width = 66
		}
		if got := len([]rune(shahTunnelHeaderArt[i])); got != width {
			t.Errorf("header line %d has visual width %d; want %d", i+1, got, width)
		}
	}
}

func TestShahTunnelRouteDiagram(t *testing.T) {
	wantContains := []string{
		"NETWORK ROUTE  /  TCP FORWARDING",
		"CLIENT ── TCP ──▶ HUB ═ TLS 1.3 + TOKEN AUTH ═▶ AGENT",
		"PATHS: TCP/TLS | WS/TLS | H2 CONNECT | H1 CONNECT",
		"OPTION 7: ADAPTIVE FAILOVER ACROSS 4 PATHS",
		"CERT PINNING • TOKEN AUTH • TLS 1.3",
	}
	if len(shahTunnelRouteArt) != 7 {
		t.Fatalf("route diagram has %d lines; want 7", len(shahTunnelRouteArt))
	}
	for i, line := range shahTunnelRouteArt {
		if got := len([]rune(line)); got != 66 {
			t.Errorf("route diagram line %d has width %d; want 66: %q", i+1, got, line)
		}
	}
	for _, want := range wantContains {
		found := false
		for _, line := range shahTunnelRouteArt {
			if strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("route diagram is missing %q", want)
		}
	}
}

func TestTLSConfigRequiresTLS13AndAgentPinsCertificate(t *testing.T) {
	serverConfig := hubTLSConfig(tls.Certificate{})
	if serverConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("Hub minimum TLS version = %d; want TLS 1.3", serverConfig.MinVersion)
	}
	if len(serverConfig.NextProtos) != 0 {
		t.Fatalf("raw tunnel control channel should not advertise HTTP ALPN: %v", serverConfig.NextProtos)
	}

	der := []byte("synthetic DER bytes used for a callback unit test")
	pin := sha256.Sum256(der)
	clientConfig := agentTLSConfig(pin[:], "edge.example.net")
	if clientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("Agent minimum TLS version = %d; want TLS 1.3", clientConfig.MinVersion)
	}
	if clientConfig.ServerName != "edge.example.net" {
		t.Fatalf("Agent TLS SNI = %q; want edge.example.net", clientConfig.ServerName)
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("certificate pin callback accepted a connection with no peer certificate")
	}
	if err := clientConfig.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: der}}}); err != nil {
		t.Fatalf("certificate with matching pin was rejected: %v", err)
	}
	wrongPin := make([]byte, sha256.Size)
	wrongPin[0] = 1
	if err := agentTLSConfig(wrongPin, "edge.example.net").VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: der}}}); err == nil {
		t.Fatal("certificate with mismatching pin was accepted")
	}
}

func TestAuthProtocolRequiresExactTokenLine(t *testing.T) {
	token := strings.Repeat("a", 64)
	for _, line := range []string{"RREV3 " + token + "\n", "RREV3 " + token + "\r\n"} {
		if got := authProtocol(line, token); got != "RREV3" {
			t.Errorf("authProtocol(%q) = %q; want RREV3", line, got)
		}
	}
	for _, line := range []string{
		" RREV3 " + token + "\n",
		"RREV3 " + token + " \n",
		"RREV3 " + token + "x\n",
		"RREV2 " + token + "\n",
	} {
		if got := authProtocol(line, token); got != "" {
			t.Errorf("authProtocol accepted malformed line %q", line)
		}
	}
}

func TestAcceptRetryDelayIsBounded(t *testing.T) {
	if got := acceptRetryDelay(0); got != 25*time.Millisecond {
		t.Fatalf("initial accept backoff = %s; want 25ms", got)
	}
	for _, attempt := range []int{0, 1, 2, 3, 4, 10, 100} {
		if got := acceptRetryDelay(attempt); got > time.Second {
			t.Errorf("accept backoff for attempt %d = %s; exceeds 1s cap", attempt, got)
		}
	}
	if !isRetryableAcceptError(syscall.EMFILE) {
		t.Fatal("file descriptor exhaustion should be treated as a transient accept error")
	}
	if isRetryableAcceptError(net.ErrClosed) {
		t.Fatal("closed listeners should not be retried")
	}
}

func TestValidateTLSServerName(t *testing.T) {
	for _, host := range []string{"edge.example.net", "xn--bcher-kva.example", "my-host.internal"} {
		if !validTLSServerName(host) {
			t.Errorf("valid TLS server name rejected: %q", host)
		}
	}
	for _, host := range []string{"", "192.0.2.1", "https://edge.example.net", "edge.example.net:443", "-bad.example", "bad-.example", "bad..example", "bad_name.example", " edge.example.net"} {
		if validTLSServerName(host) {
			t.Errorf("invalid TLS server name accepted: %q", host)
		}
	}
}

func TestAgentTLS13PinnedHandshake(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "hub.crt")
	keyPath := filepath.Join(dir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load test certificate: %v", err)
	}
	pin, err := normalizeFingerprint(fingerprint)
	if err != nil {
		t.Fatalf("decode generated fingerprint: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, hubTLSConfig(cert))
	defer tlsListener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := tlsListener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			serverDone <- errors.New("accepted connection is not TLS")
			return
		}
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			serverDone <- handshakeErr
			return
		}
		state := tlsConn.ConnectionState()
		if got := state.Version; got != tls.VersionTLS13 {
			serverDone <- fmt.Errorf("negotiated TLS version %d; want TLS 1.3", got)
			return
		}
		if state.ServerName != "edge.example.net" {
			serverDone <- fmt.Errorf("received SNI %q; want edge.example.net", state.ServerName)
			return
		}
		serverDone <- nil
	}()

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	client, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), agentTLSConfig(pin, "edge.example.net"))
	if err != nil {
		t.Fatalf("TLS 1.3 client handshake with matching pin failed: %v", err)
	}
	if got := client.ConnectionState().Version; got != tls.VersionTLS13 {
		_ = client.Close()
		t.Fatalf("client negotiated TLS version %d; want TLS 1.3", got)
	}
	_ = client.Close()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server handshake failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server handshake did not complete")
	}
}

func TestAdaptiveCandidatesCanIncludeReality(t *testing.T) {
	legacy := adaptiveTransportCandidates(transportTCP)
	if len(legacy) != 4 {
		t.Fatalf("legacy adaptive candidate count = %d; want 4", len(legacy))
	}
	for _, mode := range legacy {
		if mode == transportReality {
			t.Fatal("REALITY must not be included without explicit Agent configuration")
		}
	}
	withReality := adaptiveTransportCandidates(transportReality, true)
	if len(withReality) != 5 || withReality[0] != transportReality {
		t.Fatalf("adaptive candidates with saved REALITY preference = %#v; want 5 and REALITY first", withReality)
	}
	found := false
	for _, mode := range withReality {
		if mode == transportReality {
			found = true
		}
	}
	if !found {
		t.Fatal("REALITY missing from configured Adaptive candidates")
	}
}

func TestAdaptiveRealityDefaultPorts(t *testing.T) {
	hub := Config{Role: "hub", Transport: transportAdaptive, ControlListen: "0.0.0.0:9443"}
	got, err := realityHubListenAddress(hub)
	if err != nil || got != "0.0.0.0:9446" {
		t.Fatalf("adaptive REALITY listen address = %q, err=%v; want 0.0.0.0:9446", got, err)
	}
	agent := Config{Role: "agent", Transport: transportAdaptive, HubAddr: "203.0.113.8:9443"}
	got, err = realityAgentAddress(agent)
	if err != nil || got != "203.0.113.8:9446" {
		t.Fatalf("adaptive REALITY agent address = %q, err=%v; want 203.0.113.8:9446", got, err)
	}
	if got, err = realityAgentAddress(Config{Role: "agent", Transport: transportReality, HubAddr: "203.0.113.8:9443", RealityAddr: "203.0.113.8:9555"}); err != nil || got != "203.0.113.8:9443" {
		t.Fatalf("standalone REALITY address = %q, err=%v; want existing control address despite an Adaptive override", got, err)
	}
	if got, err = realityHubListenAddress(Config{Role: "hub", Transport: transportReality, ControlListen: "0.0.0.0:9443", RealityListen: "0.0.0.0:9555"}); err != nil || got != "0.0.0.0:9443" {
		t.Fatalf("standalone REALITY listener = %q, err=%v; want existing control listener despite an Adaptive override", got, err)
	}
	if got, err = realityAgentAddress(Config{Role: "agent", Transport: transportAdaptive, HubAddr: "203.0.113.8:9443", RealityAddr: "203.0.113.8:9555"}); err != nil || got != "203.0.113.8:9555" {
		t.Fatalf("custom Adaptive REALITY address = %q, err=%v; want configured override", got, err)
	}
	if got, err = realityHubListenAddress(Config{Role: "hub", Transport: transportAdaptive, ControlListen: "0.0.0.0:9443", RealityListen: "0.0.0.0:9555"}); err != nil || got != "0.0.0.0:9555" {
		t.Fatalf("custom Adaptive REALITY listener = %q, err=%v; want configured override", got, err)
	}
}

func TestUTLSAgentTLS13PinnedHandshakeProfiles(t *testing.T) {
	for _, profile := range []string{"chrome", "firefox", "edge", "randomized"} {
		t.Run(profile, func(t *testing.T) {
			dir := t.TempDir()
			certPath, keyPath := filepath.Join(dir, "hub.crt"), filepath.Join(dir, "hub.key")
			fingerprint, err := generateCertificate(certPath, keyPath)
			if err != nil {
				t.Fatalf("generate test certificate: %v", err)
			}
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("load test certificate: %v", err)
			}
			pin, err := normalizeFingerprint(fingerprint)
			if err != nil {
				t.Fatalf("decode generated fingerprint: %v", err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer listener.Close()
			tlsListener := tls.NewListener(listener, hubTLSConfig(cert))
			defer tlsListener.Close()
			serverResult := make(chan error, 1)
			go func() {
				conn, acceptErr := tlsListener.Accept()
				if acceptErr != nil {
					serverResult <- acceptErr
					return
				}
				defer conn.Close()
				tlsConn := conn.(*tls.Conn)
				if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
					serverResult <- handshakeErr
					return
				}
				state := tlsConn.ConnectionState()
				if state.Version != tls.VersionTLS13 {
					serverResult <- fmt.Errorf("server negotiated TLS version %d; want TLS 1.3", state.Version)
					return
				}
				if state.ServerName != "edge.example.net" {
					serverResult <- fmt.Errorf("server received SNI %q; want edge.example.net", state.ServerName)
					return
				}
				serverResult <- nil
			}()
			d := &net.Dialer{Timeout: 3 * time.Second}
			raw, err := d.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatalf("dial local listener: %v", err)
			}
			client, err := dialUTLSConnWithPin(raw, pin, "edge.example.net", nil, profile)
			if err != nil {
				t.Fatalf("uTLS handshake with %s profile failed: %v", profile, err)
			}
			_ = client.Close()
			select {
			case serverErr := <-serverResult:
				if serverErr != nil {
					t.Fatalf("server handshake: %v", serverErr)
				}
			case <-time.After(4 * time.Second):
				t.Fatal("server handshake did not complete")
			}
		})
	}
}

func TestRealityProbeFallbackReturnsCoverSiteResponse(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cover.crt"), filepath.Join(dir, "cover.key")
	if _, err := generateCertificate(certPath, keyPath); err != nil {
		t.Fatalf("generate cover certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load cover certificate: %v", err)
	}
	coverRaw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen cover site: %v", err)
	}
	coverServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "cover-site-ok")
	})}
	go func() {
		_ = coverServer.Serve(tls.NewListener(coverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
	}()
	defer coverServer.Close()

	priv, pub, err := generateRealityKeyPair()
	if err != nil {
		t.Fatalf("generate REALITY key pair: %v", err)
	}
	realityCfg, err := makeRealityServerConfig(Config{
		Transport: transportReality, RealityDest: coverRaw.Addr().String(), RealitySNI: "localhost",
		RealityPrivateKey: priv, RealityPublicKey: pub, RealityShortID: "0102030405060708",
	})
	if err != nil {
		t.Fatalf("prepare REALITY server: %v", err)
	}
	realityListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen REALITY test endpoint: %v", err)
	}
	defer realityListener.Close()
	h := &hubServer{cfg: Config{Transport: transportReality, Token: strings.Repeat("a", 64)}, sessions: make(map[*hubSession]struct{}), pendingPublic: make(chan struct{}, 8)}
	go func() {
		for {
			raw, acceptErr := realityListener.Accept()
			if acceptErr != nil {
				return
			}
			go h.serveRealityAgent(raw, realityCfg)
		}
	}()

	d := &net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.Dial("tcp", realityListener.Addr().String())
	if err != nil {
		t.Fatalf("dial probe endpoint: %v", err)
	}
	probe := tls.Client(raw, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	_ = probe.SetDeadline(time.Now().Add(5 * time.Second))
	if err := probe.Handshake(); err != nil {
		_ = probe.Close()
		t.Fatalf("standard TLS probe did not receive cover-site handshake: %v", err)
	}
	if _, err := io.WriteString(probe, "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"); err != nil {
		_ = probe.Close()
		t.Fatalf("write cover-site request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(probe), &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = probe.Close()
		t.Fatalf("read cover-site response: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	_ = probe.Close()
	if readErr != nil {
		t.Fatalf("read cover-site body: %v", readErr)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "cover-site-ok" {
		t.Fatalf("probe response = status %d body %q; want 200 and cover-site-ok", resp.StatusCode, body)
	}
}

func TestRealityShortIDNormalization(t *testing.T) {
	got, err := normalizeRealityShortID("0102")
	if err != nil {
		t.Fatalf("normalize short ID: %v", err)
	}
	want := [8]byte{0x01, 0x02}
	if got != want {
		t.Fatalf("normalized short ID = %x; want %x", got, want)
	}
	full, err := normalizeRealityShortID("0011223344556677")
	if err != nil {
		t.Fatalf("normalize full short ID: %v", err)
	}
	if full != [8]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77} {
		t.Fatalf("unexpected full short ID bytes: %x", full)
	}
	for _, invalid := range []string{"", "0", "123", "zz", "001122334455667788"} {
		if _, err := normalizeRealityShortID(invalid); err == nil {
			t.Errorf("invalid short ID %q was accepted", invalid)
		}
	}
}

func TestRealityKeyPairEncoding(t *testing.T) {
	privateKey, publicKey, err := generateRealityKeyPair()
	if err != nil {
		t.Fatalf("generate REALITY key pair: %v", err)
	}
	priv, err := decodeRealityKey(privateKey, 32)
	if err != nil || len(priv) != 32 {
		t.Fatalf("decode private key: len=%d err=%v", len(priv), err)
	}
	pub, err := decodeRealityKey(publicKey, 32)
	if err != nil || len(pub) != 32 {
		t.Fatalf("decode public key: len=%d err=%v", len(pub), err)
	}
	if err := validateRealityKeyPair(privateKey, publicKey); err != nil {
		t.Fatalf("matching REALITY key pair rejected: %v", err)
	}
	_, otherPublic, err := generateRealityKeyPair()
	if err != nil {
		t.Fatalf("generate second X25519 key pair: %v", err)
	}
	if err := validateRealityKeyPair(privateKey, otherPublic); err == nil {
		t.Fatal("mismatched REALITY key pair was accepted")
	}
	if _, err := decodeRealityKey("not-base64!", 32); err == nil {
		t.Fatal("invalid REALITY key encoding was accepted")
	}
}

func TestRealityClientHelloFingerprints(t *testing.T) {
	for _, name := range []string{"", "chrome", "firefox", "edge", "randomized", "random"} {
		if _, err := realityClientHelloID(name); err != nil {
			t.Errorf("fingerprint %q rejected: %v", name, err)
		}
	}
	if _, err := realityClientHelloID("unknown-browser"); err == nil {
		t.Fatal("unknown ClientHello fingerprint was accepted")
	}
	if got, _ := realityClientHelloID("chrome"); got != utls.HelloChrome_133 {
		t.Fatalf("REALITY chrome profile = %#v; want explicitly pinned Chrome 133 hybrid profile", got)
	}
	if !validTransportMode(transportReality) {
		t.Fatal("REALITY transport is not accepted by the config policy")
	}
	if got := normalizeConfig(Config{Role: "agent", Transport: transportReality}).RealityFingerprint; got != "chrome" {
		t.Fatalf("default REALITY fingerprint = %q; want chrome", got)
	}
}

func TestRealityChromeProfileOffersRequiredKeyShares(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	id, err := realityClientHelloID("chrome")
	if err != nil {
		t.Fatalf("resolve chrome REALITY profile: %v", err)
	}
	conn := utls.UClient(raw, &utls.Config{ServerName: "www.cloudflare.com", MinVersion: utls.VersionTLS13}, id)
	if err := conn.BuildHandshakeState(); err != nil {
		t.Fatalf("build Chrome 133 ClientHello: %v", err)
	}
	shares := conn.HandshakeState.State13.KeyShareKeys
	if shares.Ecdhe == nil {
		t.Fatal("Chrome 133 ClientHello did not create the required standalone X25519 key share")
	}
	if shares.MlkemEcdhe == nil {
		t.Fatal("Chrome 133 ClientHello did not create the required X25519MLKEM768 hybrid key share")
	}
}

func TestRealityHandledFallbackError(t *testing.T) {
	if !realityHandledFallback(errors.New("REALITY: processed invalid connection")) {
		t.Fatal("REALITY fallback sentinel was not recognized")
	}
	if realityHandledFallback(errors.New("REALITY: failed to dial dest")) {
		t.Fatal("non-fallback REALITY error was treated as an active fallback")
	}
	if realityHandledFallback(nil) {
		t.Fatal("nil error was treated as a fallback")
	}
}

func TestRealityAuthKeySharePrefersStandaloneX25519(t *testing.T) {
	plain, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate standalone X25519 key: %v", err)
	}
	hybrid, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate hybrid X25519 component key: %v", err)
	}
	if got := realityAuthKeyShare(plain, hybrid); got != plain {
		t.Fatal("REALITY auth key selection must prefer standalone X25519 when both shares are offered")
	}
	if got := realityAuthKeyShare(nil, hybrid); got != hybrid {
		t.Fatal("REALITY auth key selection must fall back to hybrid X25519 when standalone share is absent")
	}
	if got := realityAuthKeyShare(nil, nil); got != nil {
		t.Fatal("REALITY auth key selection must return nil when no usable key share exists")
	}
}
