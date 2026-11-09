package main

import (
	"bufio"
	"bytes"
	"context"
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
	conn, err := dialHTTP1Connect(cfg, nil)
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
	conn, err := dialHTTP2Connect(cfg, nil)
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
	if !validTransportMode(transportNewMethods) || !transportAllowed(transportNewMethods, transportTCP) || transportAllowed(transportNewMethods, transportWebSocket) {
		t.Fatal("new-methods mode must allow the authenticated TCP/TLS carrier only")
	}
	if !validTransportMode(transportAdaptiveAll) {
		t.Fatal("full adaptive mode must be a valid Hub/Agent transport policy")
	}
	for _, mode := range []string{transportTCP, transportWebSocket, transportHTTP2, transportHTTP1} {
		if !transportAllowed(transportAdaptiveAll, mode) {
			t.Fatalf("full adaptive Hub policy rejected native transport %q", mode)
		}
	}
	if !transportModeAllowsHTTP2(transportAdaptiveAll) || !transportModeAllowsHTTP1(transportAdaptiveAll) {
		t.Fatal("full adaptive Hub policy must open both CONNECT listener ports")
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

func TestNewMethodsModeConnectsThroughConfiguredSOCKS5Underlay(t *testing.T) {
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
		t.Fatalf("normalize certificate pin: %v", err)
	}
	const token = "a84c4e76e42a42e294cd89d41fcf47aea84c4e76e42a42e294cd89d41fcf47ae"

	hubListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hubListener.Close()
	h := &hubServer{cfg: Config{Role: "hub", Transport: transportNewMethods, Token: token}, sessions: make(map[*hubSession]struct{})}
	go func() {
		for {
			conn, acceptErr := hubListener.Accept()
			if acceptErr != nil {
				return
			}
			go h.serveAgent(conn, hubTLSConfig(cert))
		}
	}()
	socksAddr, _ := startTestSOCKS5Forwarder(t, hubListener.Addr().String())
	cfg := Config{
		Role: "agent", Transport: transportNewMethods, HubAddr: hubListener.Addr().String(),
		TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1,
		UnderlayPaths: []UnderlayPath{{Method: underlayPsiphon, Endpoint: socksAddr}},
	}
	channel := 91
	agentPreferredTransport.Delete(channel)
	t.Cleanup(func() { agentPreferredTransport.Delete(channel) })
	agentDone := make(chan error, 1)
	go func() { agentDone <- connectAndRunAgent(cfg, pin, channel) }()
	deadline := time.Now().Add(5 * time.Second)
	for h.sessionCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.sessionCount() == 0 {
		t.Fatal("Agent did not establish an authenticated tunnel through the configured SOCKS5 underlay")
	}
	if got, ok := agentPreferredTransport.Load(channel); !ok || got != "underlay/psiphon" {
		t.Fatalf("last successful new-method path = %v (present=%v); want underlay/psiphon", got, ok)
	}
	h.mu.RLock()
	var active *hubSession
	for session := range h.sessions {
		active = session
		break
	}
	h.mu.RUnlock()
	if active == nil {
		t.Fatal("expected active Hub session")
	}
	active.shutdown()
	select {
	case <-agentDone:
	case <-time.After(4 * time.Second):
		t.Fatal("Agent did not stop after its test Hub session closed")
	}
}

func TestFullAdaptiveFallsBackFromNativeTransportsToNewUnderlay(t *testing.T) {
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
		t.Fatalf("normalize certificate pin: %v", err)
	}
	const token = "b84c4e76e42a42e294cd89d41fcf47aea84c4e76e42a42e294cd89d41fcf47ae"

	hubListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hubListener.Close()
	h := &hubServer{cfg: Config{Role: "hub", Transport: transportAdaptiveAll, Token: token}, sessions: make(map[*hubSession]struct{})}
	go func() {
		for {
			conn, acceptErr := hubListener.Accept()
			if acceptErr != nil {
				return
			}
			go h.serveAgent(conn, hubTLSConfig(cert))
		}
	}()
	// The proxy intentionally maps the configured (unreachable) Hub address to
	// the test Hub. This makes all four direct native attempts fail while the
	// external underlay succeeds, exercising the option-8 fallback path.
	socksAddr, socksListener := startTestSOCKS5Forwarder(t, hubListener.Addr().String())
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachableHub := closed.Addr().String()
	_ = closed.Close()
	cfg := Config{
		Role: "agent", Transport: transportAdaptiveAll, HubAddr: unreachableHub,
		TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1,
		UnderlayPaths: []UnderlayPath{
			{Method: underlayMASQUE, Endpoint: socksAddr},
			{Method: underlayBackhaul, Endpoint: hubListener.Addr().String()},
		},
	}
	channel := 92
	agentPreferredTransport.Delete(channel)
	t.Cleanup(func() { agentPreferredTransport.Delete(channel) })
	agentDone := make(chan error, 1)
	go func() { agentDone <- connectAndRunAgent(cfg, pin, channel) }()
	deadline := time.Now().Add(8 * time.Second)
	for h.sessionCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.sessionCount() == 0 {
		t.Fatal("Full Adaptive Failover did not reach the new MASQUE underlay after native transports failed")
	}
	if got, ok := agentPreferredTransport.Load(channel); !ok || got != "underlay/masque" {
		t.Fatalf("full adaptive preferred path = %v (present=%v); want underlay/masque", got, ok)
	}
	h.mu.RLock()
	var active *hubSession
	for session := range h.sessions {
		active = session
		break
	}
	h.mu.RUnlock()
	if active == nil {
		t.Fatal("expected active Hub session after adaptive fallback")
	}
	// Tear down the active MASQUE-compatible proxy. The same lane must move to
	// its next configured healthy underlay (Backhaul local forward) automatically.
	_ = socksListener.Close()
	active.shutdown()
	switchDeadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(switchDeadline) {
		preferred, ok := agentPreferredTransport.Load(channel)
		if ok && preferred == "underlay/backhaul" && h.sessionCount() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if preferred, ok := agentPreferredTransport.Load(channel); !ok || preferred != "underlay/backhaul" || h.sessionCount() == 0 {
		t.Fatalf("lane did not fail over from MASQUE to Backhaul: preferred=%v present=%v sessions=%d", preferred, ok, h.sessionCount())
	}
	h.mu.RLock()
	var backhaulSession *hubSession
	for session := range h.sessions {
		backhaulSession = session
		break
	}
	h.mu.RUnlock()
	if backhaulSession == nil {
		t.Fatal("expected active Backhaul-backed Hub session")
	}
	backhaulSession.shutdown()
	select {
	case <-agentDone:
	case <-time.After(4 * time.Second):
		t.Fatal("Agent did not stop after the Backhaul test session closed")
	}
}

func startTestSOCKS5Forwarder(t *testing.T, forwardTo string) (string, net.Listener) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			client, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()
				var greeting [3]byte
				if _, e := io.ReadFull(client, greeting[:]); e != nil || !bytes.Equal(greeting[:], []byte{0x05, 0x01, 0x00}) {
					return
				}
				if _, e := client.Write([]byte{0x05, 0x00}); e != nil {
					return
				}
				var header [4]byte
				if _, e := io.ReadFull(client, header[:]); e != nil || header[0] != 0x05 || header[1] != 0x01 {
					return
				}
				switch header[3] {
				case 0x01:
					if _, e := io.CopyN(io.Discard, client, 4+2); e != nil {
						return
					}
				case 0x04:
					if _, e := io.CopyN(io.Discard, client, 16+2); e != nil {
						return
					}
				case 0x03:
					var n [1]byte
					if _, e := io.ReadFull(client, n[:]); e != nil {
						return
					}
					if _, e := io.CopyN(io.Discard, client, int64(n[0])+2); e != nil {
						return
					}
				default:
					return
				}
				upstream, e := net.DialTimeout("tcp", forwardTo, 3*time.Second)
				if e != nil {
					_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				if _, e = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); e != nil {
					return
				}
				done := make(chan struct{}, 1)
				go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
				_, _ = io.Copy(client, upstream)
				select {
				case <-done:
				case <-time.After(time.Second):
				}
			}(client)
		}
	}()
	return listener.Addr().String(), listener
}

func TestAdaptiveAllBuildsTenCandidatePaths(t *testing.T) {
	paths := []UnderlayPath{
		{Method: underlayMASQUE, Endpoint: "127.0.0.1:10808"},
		{Method: underlayWARP},
		{Method: underlayWARPOnWARP, Endpoint: "127.0.0.1:10809"},
		{Method: underlayTOR, Endpoint: "127.0.0.1:9050"},
		{Method: underlayPsiphon, Endpoint: "127.0.0.1:1080"},
		{Method: underlayBackhaul, Endpoint: "127.0.0.1:12080"},
	}
	candidates := adaptiveAllTransportCandidates("", paths)
	if len(candidates) != 10 {
		t.Fatalf("full adaptive produced %d candidates; want 10: %+v", len(candidates), candidates)
	}
	wantNative := []string{transportTCP, transportWebSocket, transportHTTP2, transportHTTP1}
	for i, want := range wantNative {
		if candidates[i].mode != want || candidates[i].path != nil {
			t.Fatalf("native candidate #%d = %+v; want direct %q", i+1, candidates[i], want)
		}
	}
	for i, path := range paths {
		candidate := candidates[i+4]
		if candidate.mode != transportTCP || candidate.path == nil || candidate.path.Method != path.Method {
			t.Fatalf("underlay candidate #%d = %+v; want TCP carrier over %q", i+1, candidate, path.Method)
		}
	}
	preferred := adaptiveAllTransportCandidates("underlay/tor", paths)
	if preferred[0].key != "underlay/tor" {
		t.Fatalf("preferred route was not tried first: %+v", preferred[0])
	}
}

func TestValidateUnderlayPaths(t *testing.T) {
	valid := []UnderlayPath{
		{Method: underlayMASQUE, Endpoint: "127.0.0.1:10808"},
		{Method: underlayWARP},
		{Method: underlayWARPOnWARP, Endpoint: "127.0.0.1:10809"},
		{Method: underlayTOR, Endpoint: "127.0.0.1:9050"},
		{Method: underlayPsiphon, Endpoint: "127.0.0.1:1080"},
		{Method: underlayBackhaul, Endpoint: "127.0.0.1:12080"},
	}
	if err := validateUnderlayPaths(valid); err != nil {
		t.Fatalf("valid six-method configuration rejected: %v", err)
	}
	for _, bad := range [][]UnderlayPath{
		{{Method: underlayTOR}},
		{{Method: underlayWARP, Endpoint: "127.0.0.1:9050"}},
		{{Method: "unknown", Endpoint: "127.0.0.1:1"}},
		{{Method: underlayBackhaul, Endpoint: "not-an-address"}},
		{{Method: underlayTOR, Endpoint: "127.0.0.1:9050"}, {Method: underlayTOR, Endpoint: "127.0.0.1:9051"}},
	} {
		if err := validateUnderlayPaths(bad); err == nil {
			t.Fatalf("invalid underlay configuration accepted: %+v", bad)
		}
	}
}

func TestProbeUnderlayReadyAcceptsNoAuthSOCKS5(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var greeting [3]byte
		if _, readErr := io.ReadFull(conn, greeting[:]); readErr != nil {
			serverErr <- readErr
			return
		}
		if greeting != [3]byte{0x05, 0x01, 0x00} {
			serverErr <- fmt.Errorf("unexpected SOCKS5 greeting: %v", greeting)
			return
		}
		_, writeErr := conn.Write([]byte{0x05, 0x00})
		serverErr <- writeErr
	}()

	if err := probeUnderlayReady(UnderlayPath{Method: underlayMASQUE, Endpoint: ln.Addr().String()}); err != nil {
		t.Fatalf("expected ready SOCKS5 endpoint, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("SOCKS5 probe server: %v", err)
	}
}

func TestProbeUnderlayReadyRejectsSOCKS5RequiringAuthentication(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		var greeting [3]byte
		if _, readErr := io.ReadFull(conn, greeting[:]); readErr != nil {
			serverErr <- readErr
			return
		}
		_, writeErr := conn.Write([]byte{0x05, 0xff})
		serverErr <- writeErr
	}()

	err = probeUnderlayReady(UnderlayPath{Method: underlayTOR, Endpoint: ln.Addr().String()})
	if err == nil || !strings.Contains(err.Error(), "unauthenticated SOCKS5") {
		t.Fatalf("expected no-auth SOCKS5 validation error, got: %v", err)
	}
	if serverErr := <-serverErr; serverErr != nil {
		t.Fatalf("SOCKS5 probe server: %v", serverErr)
	}
}

func TestProbeUnderlayReadyAcceptsBackhaulForward(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		close(accepted)
	}()
	if err := probeUnderlayReady(UnderlayPath{Method: underlayBackhaul, Endpoint: ln.Addr().String()}); err != nil {
		t.Fatalf("expected reachable Backhaul forward, got: %v", err)
	}
	<-accepted
}

func TestSOCKS5DialContextPreservesRemoteHostname(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		greeting := make([]byte, 3)
		if _, e := io.ReadFull(conn, greeting); e != nil {
			serverErr <- e
			return
		}
		if !bytes.Equal(greeting, []byte{0x05, 0x01, 0x00}) {
			serverErr <- fmt.Errorf("unexpected SOCKS5 greeting %v", greeting)
			return
		}
		if _, e := conn.Write([]byte{0x05, 0x00}); e != nil {
			serverErr <- e
			return
		}
		var header [5]byte
		if _, e := io.ReadFull(conn, header[:]); e != nil {
			serverErr <- e
			return
		}
		if header[0] != 0x05 || header[1] != 0x01 || header[3] != 0x03 {
			serverErr <- fmt.Errorf("expected SOCKS5 domain CONNECT request, got %v", header)
			return
		}
		host := make([]byte, int(header[4]))
		if _, e := io.ReadFull(conn, host); e != nil {
			serverErr <- e
			return
		}
		var port [2]byte
		if _, e := io.ReadFull(conn, port[:]); e != nil {
			serverErr <- e
			return
		}
		if string(host) != "hub-example.onion" || binary.BigEndian.Uint16(port[:]) != 9443 {
			serverErr <- fmt.Errorf("proxy got target %s:%d; wanted hub-example.onion:9443", host, binary.BigEndian.Uint16(port[:]))
			return
		}
		if _, e := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x24, 0x00}); e != nil {
			serverErr <- e
			return
		}
		_, e := conn.Write([]byte("ready"))
		serverErr <- e
	}()

	conn, err := socks5DialContext(context.Background(), listener.Addr().String(), "hub-example.onion:9443")
	if err != nil {
		t.Fatalf("SOCKS5 dial: %v", err)
	}
	defer conn.Close()
	got := make([]byte, 5)
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatalf("read tunneled payload: %v", err)
	}
	if string(got) != "ready" {
		t.Fatalf("payload = %q; want ready", got)
	}
	if err = <-serverErr; err != nil {
		t.Fatalf("SOCKS5 fake server: %v", err)
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

func TestTunnelIDIsStableAndSystemdSafe(t *testing.T) {
	for _, name := range []string{"iran-main", "Outside Server", "ایران-خارج"} {
		id := tunnelID(name)
		if id == "" || len(id) > 48 {
			t.Fatalf("tunnelID(%q) produced invalid length/value %q", name, id)
		}
		for _, r := range id {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
				t.Fatalf("tunnelID(%q) contains unsafe rune %q in %q", name, r, id)
			}
		}
		if again := tunnelID(name); again != id {
			t.Fatalf("tunnelID(%q) is not stable: %q then %q", name, id, again)
		}
	}
	if tunnelID("ایران") == tunnelID("خارج") {
		t.Fatal("different non-ASCII tunnel names must not collide")
	}
}

func TestUploadFlowControlWindowIsExpanded(t *testing.T) {
	if streamWindowFrames < 256 {
		t.Fatalf("stream window = %d frames; want at least 256", streamWindowFrames)
	}
	if maxFrame < 64*1024 {
		t.Fatalf("maximum frame = %d bytes; want at least 64 KiB", maxFrame)
	}
	if got := int64(streamWindowFrames) * int64(maxFrame); got < 16<<20 {
		t.Fatalf("per-stream in-flight window = %d bytes; want at least 16 MiB", got)
	}
	if maxQueuedPayloadBytes < 64<<20 {
		t.Fatalf("global queued payload budget = %d bytes; want at least 64 MiB", maxQueuedPayloadBytes)
	}
}

func TestListenAddressConflictDetection(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.0.0.0:9443", "127.0.0.1:9443", true},
		{"127.0.0.1:9443", "127.0.0.1:9443", true},
		{"127.0.0.1:9443", "127.0.0.1:9444", false},
		{"192.0.2.1:443", "198.51.100.2:443", false},
		{"[::]:443", "192.0.2.1:443", true},
	}
	for _, tc := range cases {
		if got := listenAddressesConflict(tc.a, tc.b); got != tc.want {
			t.Errorf("listenAddressesConflict(%q, %q) = %v; want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
