package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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
	proxyAddress := startTestSOCKS5Relay(t, h1Listener.Addr().String())
	cfg := Config{Role: "agent", Transport: transportHTTP1, Underlay: underlayPsiphon, PsiphonProxy: proxyAddress, HubAddr: control.Addr().String(), TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1}
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

	proxyAddress := startTestSOCKS5Relay(t, h2Listener.Addr().String())
	cfg := Config{Role: "agent", Transport: transportHTTP2, Underlay: underlayPsiphon, PsiphonProxy: proxyAddress, HubAddr: baseAddr, TLSServerName: "localhost", Token: token, Fingerprint: fingerprint, TunnelChannels: 1}
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

func startTestSOCKS5Relay(t *testing.T, target string) string {
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
				_ = client.SetDeadline(time.Now().Add(5 * time.Second))
				var greeting [3]byte
				if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting != [3]byte{0x05, 0x01, 0x00} {
					return
				}
				if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
					return
				}
				var header [4]byte
				if _, err := io.ReadFull(client, header[:]); err != nil || header[0] != 0x05 || header[1] != 0x01 {
					return
				}
				switch header[3] {
				case 0x01:
					var address [6]byte
					if _, err := io.ReadFull(client, address[:]); err != nil {
						return
					}
				case 0x04:
					var address [18]byte
					if _, err := io.ReadFull(client, address[:]); err != nil {
						return
					}
				case 0x03:
					var size [1]byte
					if _, err := io.ReadFull(client, size[:]); err != nil {
						return
					}
					address := make([]byte, int(size[0])+2)
					if _, err := io.ReadFull(client, address); err != nil {
						return
					}
				default:
					return
				}
				server, err := net.DialTimeout("tcp", target, 3*time.Second)
				if err != nil {
					_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer server.Close()
				if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				_ = client.SetDeadline(time.Time{})
				copyDone := make(chan struct{}, 1)
				go func() { _, _ = io.Copy(server, client); close(copyDone) }()
				_, _ = io.Copy(client, server)
				_ = server.Close()
				select {
				case <-copyDone:
				case <-time.After(time.Second):
				}
			}(client)
		}
	}()
	return listener.Addr().String()
}

func TestAgentTransportsActuallyDialHubThroughPsiphonSOCKS5(t *testing.T) {
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
	token := strings.Repeat("a1", 32)

	for index, mode := range []string{transportTCP, transportWebSocket} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			h := &hubServer{cfg: Config{Role: "hub", Transport: transportAdaptive, Token: token}, sessions: make(map[*hubSession]struct{})}
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					h.serveAgent(conn, hubTLSConfig(cert))
				}
			}()
			proxyAddress := startTestSOCKS5Relay(t, listener.Addr().String())
			channel := 91 + index
			agentPreferredTransport.Delete(channel)
			agentPreferredUnderlay.Delete(channel)
			t.Cleanup(func() {
				agentPreferredTransport.Delete(channel)
				agentPreferredUnderlay.Delete(channel)
			})
			cfg := Config{
				Role:           "agent",
				Transport:      transportAdaptive,
				Underlay:       underlayPsiphon,
				PsiphonProxy:   proxyAddress,
				HubAddr:        "hub.example.test:" + portOf(listener.Addr().String()),
				TLSServerName:  "localhost",
				Token:          token,
				Fingerprint:    fingerprint,
				TunnelChannels: 1,
				Ports:          []PortMapping{},
			}
			agentDone := make(chan error, 1)
			go func() { agentDone <- connectAndRunAgentWithTransport(cfg, pin, channel, mode) }()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				_, underlayReady := agentPreferredUnderlay.Load(channel)
				_, transportReady := agentPreferredTransport.Load(channel)
				if h.sessionCount() > 0 && underlayReady && transportReady {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if h.sessionCount() == 0 {
				t.Fatal("Agent did not authenticate with the Hub through the SOCKS5 proxy")
			}
			if got, ok := agentPreferredUnderlay.Load(channel); !ok || got != underlayPsiphon {
				t.Fatalf("Agent did not remember Psiphon egress after success: got=%v present=%v", got, ok)
			}
			if got, ok := agentPreferredTransport.Load(channel); !ok || got != mode {
				t.Fatalf("Agent did not remember successful transport: got=%v present=%v", got, ok)
			}
			h.mu.RLock()
			var active *hubSession
			for session := range h.sessions {
				active = session
				break
			}
			h.mu.RUnlock()
			if active == nil {
				t.Fatal("expected an authenticated Hub session")
			}
			active.shutdown()
			select {
			case <-agentDone:
			case <-time.After(4 * time.Second):
				t.Fatal("Agent did not finish after test Hub session shutdown")
			}
			_ = listener.Close()
			select {
			case <-serverDone:
			case <-time.After(2 * time.Second):
				t.Fatal("Hub test handler did not exit")
			}
		})
	}
}

func TestOptionNineSwitchesFromFailedDirectPathToPsiphonSOCKS5(t *testing.T) {
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
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &hubServer{cfg: Config{Role: "hub", Transport: transportAdaptive, Token: strings.Repeat("b2", 32)}, sessions: make(map[*hubSession]struct{})}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			h.serveAgent(conn, hubTLSConfig(cert))
		}
	}()

	// Reserve then close a local TCP port so the Direct candidate fails
	// deterministically, while the test SOCKS5 proxy forwards to the live Hub.
	unavailable, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unavailableAddress := unavailable.Addr().String()
	_ = unavailable.Close()
	proxyAddress := startTestSOCKS5Relay(t, listener.Addr().String())
	channel := 109
	agentPreferredTransport.Delete(channel)
	agentPreferredUnderlay.Delete(channel)
	t.Cleanup(func() {
		agentPreferredTransport.Delete(channel)
		agentPreferredUnderlay.Delete(channel)
	})
	cfg := Config{
		Role:           "agent",
		Transport:      transportAdaptive,
		Underlay:       underlayAdaptive,
		PsiphonConfig:  "/tmp/psiphon-client.json",
		PsiphonProxy:   proxyAddress,
		HubAddr:        unavailableAddress,
		TLSServerName:  "localhost",
		Token:          strings.Repeat("b2", 32),
		Fingerprint:    fingerprint,
		TunnelChannels: 1,
		Ports:          []PortMapping{},
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- connectAndRunAgent(cfg, pin, channel) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, underlayReady := agentPreferredUnderlay.Load(channel)
		_, transportReady := agentPreferredTransport.Load(channel)
		if h.sessionCount() > 0 && underlayReady && transportReady {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.sessionCount() == 0 {
		t.Fatal("option 9 did not reach the Hub after the direct path failed")
	}
	if got, ok := agentPreferredUnderlay.Load(channel); !ok || got != underlayPsiphon {
		t.Fatalf("option 9 did not switch to Psiphon: got=%v present=%v", got, ok)
	}
	if got, ok := agentPreferredTransport.Load(channel); !ok || got != transportTCP {
		t.Fatalf("option 9 used unexpected inner transport after fallback: got=%v present=%v", got, ok)
	}
	_ = listener.Close()
	h.mu.RLock()
	var active *hubSession
	for session := range h.sessions {
		active = session
		break
	}
	h.mu.RUnlock()
	if active != nil {
		active.shutdown()
	}
	select {
	case <-agentDone:
	case <-time.After(10 * time.Second):
		t.Fatal("option 9 did not finish its remaining fallback attempts")
	}
	select {
	case <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Hub test handler did not exit")
	}
}

func TestOptionNineRequiresAllFourInnerTransports(t *testing.T) {
	cfg := Config{
		Version:        version,
		Role:           "agent",
		Transport:      transportTCP,
		Underlay:       underlayAdaptive,
		PsiphonConfig:  "/tmp/psiphon-client.json",
		PsiphonProxy:   "127.0.0.1:1080",
		HubAddr:        "127.0.0.1:9443",
		Token:          strings.Repeat("a", 48),
		Fingerprint:    strings.Repeat("0", 64),
		TunnelChannels: 1,
		Ports:          []PortMapping{{ID: "main", Target: "127.0.0.1:443"}},
	}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("option 9 accepted a single inner transport instead of all four")
	}
	cfg.Transport = transportAdaptive
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("option 9 rejected all-protocol adaptive configuration: %v", err)
	}
}

func TestWarpUnderlayFailsClosedWhenClientIsUnavailable(t *testing.T) {
	// A selected WARP mode must never fall back to the host's ordinary route
	// when the WARP client is missing or disconnected.
	t.Setenv("PATH", t.TempDir())
	for _, underlay := range []string{underlayMASQUE, underlayWARP} {
		t.Run(underlay, func(t *testing.T) {
			cfg := Config{Transport: transportAdaptive, Underlay: underlay}
			err := connectAndRunAgent(cfg, nil, 120)
			if err == nil || !strings.Contains(err.Error(), "warp-cli is not installed") {
				t.Fatalf("selected WARP underlay did not fail closed: %v", err)
			}
		})
	}
}

func TestWarpStatusAndProtocolParsing(t *testing.T) {
	if !warpStatusConnected("Status update: Connected\n") {
		t.Fatal("connected WARP status was not recognized")
	}
	if warpStatusConnected("Status update: Disconnected\n") {
		t.Fatal("disconnected WARP status was incorrectly recognized as connected")
	}
	if !warpProtocolMatches("(network policy) WARP tunnel protocol: MASQUE\n", "MASQUE") {
		t.Fatal("MASQUE setting was not recognized")
	}
	if warpProtocolMatches("(network policy) WARP tunnel protocol: MASQUE\n", "WireGuard") {
		t.Fatal("mismatched WARP protocol was accepted")
	}
	for _, test := range []struct {
		body string
		want bool
	}{
		{body: `fl=01
warp=on
loc=DE`, want: true},
		{body: `fl=01
warp=off
loc=DE`, want: false},
		{body: "warp=online", want: false},
	} {
		if got := traceHasWarpOn(test.body); got != test.want {
			t.Errorf("traceHasWarpOn(%q) = %v; want %v", test.body, got, test.want)
		}
	}
}

func TestWarpProxyAddressFromSettings(t *testing.T) {
	for _, test := range []struct {
		name     string
		settings string
		want     string
		isProxy  bool
		wantErr  bool
	}{
		{
			name: "local proxy mode",
			settings: "Merged configuration:\n(user set) Mode: WarpProxy on port 40000\n" +
				"(consumer overrides) WARP tunnel protocol: MASQUE\n",
			want: "127.0.0.1:40000", isProxy: true,
		},
		{
			name: "system tunnel mode",
			settings: "(user set) Mode: warp+doh\n" +
				"(consumer overrides) WARP tunnel protocol: MASQUE\n",
		},
		{
			name:     "invalid port",
			settings: "(user set) Mode: WarpProxy on port 70000\n",
			isProxy:  true, wantErr: true,
		},
		{
			name:     "missing port",
			settings: "(user set) Mode: WarpProxy enabled\n",
			isProxy:  true, wantErr: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, isProxy, err := warpProxyAddressFromSettings(test.settings)
			if (err != nil) != test.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			if isProxy != test.isProxy {
				t.Fatalf("local proxy mode = %v; want %v", isProxy, test.isProxy)
			}
			if got != test.want {
				t.Fatalf("proxy address = %q; want %q", got, test.want)
			}
		})
	}
}

func TestDialAgentUnderlayUsesDetectedWarpLocalProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	warpCLI := filepath.Join(binDir, "warp-cli")
	script := "#!/bin/sh\nif [ \"$1\" = settings ]; then echo '(user set) Mode: WarpProxy on port " + port + "'; fi\n"
	if err := os.WriteFile(warpCLI, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

		// Cloudflare WarpProxy SOCKS5 no-auth negotiation.
		var greeting [3]byte
		if _, readErr := io.ReadFull(conn, greeting[:]); readErr != nil {
			serverErr <- readErr
			return
		}
		if greeting != [3]byte{0x05, 0x01, 0x00} {
			serverErr <- fmt.Errorf("unexpected SOCKS5 greeting %v", greeting)
			return
		}
		if _, writeErr := conn.Write([]byte{0x05, 0x00}); writeErr != nil {
			serverErr <- writeErr
			return
		}

		var requestHead [4]byte
		if _, readErr := io.ReadFull(conn, requestHead[:]); readErr != nil {
			serverErr <- readErr
			return
		}
		if requestHead != [4]byte{0x05, 0x01, 0x00, 0x01} {
			serverErr <- fmt.Errorf("unexpected SOCKS5 CONNECT header %v", requestHead)
			return
		}
		var targetIP [4]byte
		if _, readErr := io.ReadFull(conn, targetIP[:]); readErr != nil {
			serverErr <- readErr
			return
		}
		var portBytes [2]byte
		if _, readErr := io.ReadFull(conn, portBytes[:]); readErr != nil {
			serverErr <- readErr
			return
		}
		if net.IP(targetIP[:]).String() != "37.32.12.244" || int(portBytes[0])<<8|int(portBytes[1]) != 9448 {
			serverErr <- fmt.Errorf("unexpected SOCKS5 target %s:%d", net.IP(targetIP[:]), int(portBytes[0])<<8|int(portBytes[1]))
			return
		}
		if _, writeErr := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34}); writeErr != nil {
			serverErr <- writeErr
			return
		}

		payload := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, payload); readErr != nil {
			serverErr <- readErr
			return
		}
		_, writeErr := conn.Write(payload)
		serverErr <- writeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialAgentUnderlay(ctx, Config{Underlay: underlayMASQUE}, "tcp", "37.32.12.244:9448")
	if err != nil {
		t.Fatalf("MASQUE Agent did not use detected WarpProxy SOCKS5: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("warp")); err != nil {
		t.Fatalf("write over WARP SOCKS5 proxy: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read over WARP SOCKS5 proxy: %v", err)
	}
	if string(got) != "warp" {
		t.Fatalf("WARP SOCKS5 proxy payload = %q; want warp", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("WARP local SOCKS5 proxy: %v", err)
	}
}

func TestVerifyWarpUnderlayLocalProxyDoesNotDependOnTraceEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	binDir := t.TempDir()
	warpCLI := filepath.Join(binDir, "warp-cli")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"status) echo 'Status update: Connected';;\n" +
		"settings) printf '%s\\n' '(user set) Mode: WarpProxy on port " + port + "' '(consumer overrides) WARP tunnel protocol: MASQUE';;\n" +
		"esac\n"
	if err := os.WriteFile(warpCLI, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
		accepted <- acceptErr
	}()
	if err := verifyWarpUnderlay("MASQUE"); err != nil {
		t.Fatalf("local WarpProxy was rejected based on an external trace endpoint: %v", err)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("local WarpProxy listener was not probed: %v", err)
	}
}

func TestWireGuardRejectsWarpProxyMode(t *testing.T) {
	binDir := t.TempDir()
	warpCLI := filepath.Join(binDir, "warp-cli")
	if err := os.WriteFile(warpCLI, []byte("#!/bin/sh\necho '(user set) Mode: WarpProxy on port 40000'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := dialAgentUnderlay(ctx, Config{Underlay: underlayWARP}, "tcp", "hub.example:9443")
	if err == nil || !strings.Contains(err.Error(), "only supports the MASQUE underlay") {
		t.Fatalf("WireGuard unexpectedly accepted Local Proxy mode: %v", err)
	}
}

func TestUnderlayModesAndLoopbackValidation(t *testing.T) {
	for _, mode := range []string{underlayDirect, underlayMASQUE, underlayWARP, underlayPsiphon, underlayAdaptive} {
		if !validUnderlayMode(mode) {
			t.Fatalf("valid underlay %q was rejected", mode)
		}
	}
	for _, mode := range []string{"", "warp", "masque", "socks5://127.0.0.1:1080", "unknown"} {
		if validUnderlayMode(mode) {
			t.Fatalf("invalid underlay %q was accepted", mode)
		}
	}
	if got := normalizeConfig(Config{Role: "agent"}).Underlay; got != underlayDirect {
		t.Fatalf("legacy Agent underlay = %q; want %q", got, underlayDirect)
	}
	for _, address := range []string{"127.0.0.1:1080", "[::1]:1080"} {
		if !isLoopbackProxyAddress(address) {
			t.Errorf("loopback proxy address %q was rejected", address)
		}
	}
	for _, address := range []string{"0.0.0.0:1080", "192.0.2.10:1080", "localhost:1080", "example.com:1080", "127.0.0.1:0", "127.0.0.1:70000", "127.0.0.1:abc"} {
		if isLoopbackProxyAddress(address) {
			t.Errorf("non-loopback/invalid proxy address %q was accepted", address)
		}
	}
}

func TestAdaptiveUnderlayCandidatesPreferLastSuccessfulEgress(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // Keep this test independent of a host WARP installation.
	cfg := Config{Underlay: underlayAdaptive, PsiphonConfig: "/tmp/psiphon-client.json"}
	want := []string{underlayDirect, underlayPsiphon}
	got := adaptiveUnderlayCandidates(cfg, "")
	if !equalStrings(got, want) {
		t.Fatalf("default egress candidates = %v; want %v", got, want)
	}
	got = adaptiveUnderlayCandidates(cfg, underlayPsiphon)
	if !equalStrings(got, []string{underlayPsiphon, underlayDirect}) {
		t.Fatalf("preferred Psiphon candidates = %v", got)
	}
	got = adaptiveUnderlayCandidates(Config{Underlay: underlayAdaptive}, underlayPsiphon)
	if !equalStrings(got, []string{underlayDirect}) {
		t.Fatalf("without Psiphon config, candidates = %v; want direct only", got)
	}
}

func TestAdaptiveUnderlayCandidatesDetectWARPAndFailOver(t *testing.T) {
	binDir := t.TempDir()
	warpCLI := filepath.Join(binDir, "warp-cli")
	script := `#!/bin/sh
case "$1" in
  status) printf '%s\\n' "$FAKE_WARP_STATUS" ;;
  settings) printf '%s\\n' "$FAKE_WARP_SETTINGS" ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(warpCLI, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)
	t.Setenv("FAKE_WARP_STATUS", "Status update: Connected")
	t.Setenv("FAKE_WARP_SETTINGS", "WARP tunnel protocol: MASQUE")
	cfg := Config{Underlay: underlayAdaptive, PsiphonConfig: "/etc/shah-tunnel/psiphon-client.json"}
	if got := detectActiveWarpUnderlay(); got != underlayMASQUE {
		t.Fatalf("detected WARP mode = %q; want MASQUE", got)
	}
	if got, want := adaptiveUnderlayCandidates(cfg, ""), []string{underlayMASQUE, underlayPsiphon, underlayDirect}; !equalStrings(got, want) {
		t.Fatalf("active MASQUE candidate order = %v; want %v", got, want)
	}

	t.Setenv("FAKE_WARP_SETTINGS", "WARP tunnel protocol: WireGuard")
	if got := detectActiveWarpUnderlay(); got != underlayWARP {
		t.Fatalf("detected WARP mode = %q; want WireGuard", got)
	}
	if got, want := adaptiveUnderlayCandidates(cfg, underlayPsiphon), []string{underlayWARP, underlayPsiphon, underlayDirect}; !equalStrings(got, want) {
		t.Fatalf("active WireGuard candidate order = %v; want %v", got, want)
	}

	t.Setenv("FAKE_WARP_STATUS", "Status update: Disconnected")
	if got := detectActiveWarpUnderlay(); got != "" {
		t.Fatalf("disconnected WARP was detected as %q", got)
	}
	if got, want := adaptiveUnderlayCandidates(cfg, underlayMASQUE), []string{underlayPsiphon, underlayDirect}; !equalStrings(got, want) {
		t.Fatalf("WARP-down fallback order = %v; want %v", got, want)
	}
}

func TestSOCKS5DialerUsesRemoteHostnameAndCarriesTCP(t *testing.T) {
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := proxy.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		var greeting [3]byte
		if _, readErr := io.ReadFull(conn, greeting[:]); readErr != nil {
			serverDone <- readErr
			return
		}
		if greeting != [3]byte{0x05, 0x01, 0x00} {
			serverDone <- fmt.Errorf("unexpected SOCKS greeting: %v", greeting)
			return
		}
		if _, writeErr := conn.Write([]byte{0x05, 0x00}); writeErr != nil {
			serverDone <- writeErr
			return
		}
		var head [5]byte
		if _, readErr := io.ReadFull(conn, head[:]); readErr != nil {
			serverDone <- readErr
			return
		}
		if head[0] != 0x05 || head[1] != 0x01 || head[2] != 0x00 || head[3] != 0x03 {
			serverDone <- fmt.Errorf("expected SOCKS5 domain CONNECT, got %v", head)
			return
		}
		host := make([]byte, int(head[4]))
		if _, readErr := io.ReadFull(conn, host); readErr != nil {
			serverDone <- readErr
			return
		}
		var portBytes [2]byte
		if _, readErr := io.ReadFull(conn, portBytes[:]); readErr != nil {
			serverDone <- readErr
			return
		}
		if string(host) != "hub.example.test" || binary.BigEndian.Uint16(portBytes[:]) != 9443 {
			serverDone <- fmt.Errorf("SOCKS destination = %s:%d", string(host), binary.BigEndian.Uint16(portBytes[:]))
			return
		}
		if _, writeErr := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); writeErr != nil {
			serverDone <- writeErr
			return
		}
		if _, writeErr := conn.Write([]byte("Psiphon-path-ok")); writeErr != nil {
			serverDone <- writeErr
			return
		}
		serverDone <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialSOCKS5Context(ctx, proxy.Addr().String(), "hub.example.test:9443")
	if err != nil {
		t.Fatalf("SOCKS5 dial: %v", err)
	}
	defer conn.Close()
	got := make([]byte, len("Psiphon-path-ok"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read tunneled bytes: %v", err)
	}
	if string(got) != "Psiphon-path-ok" {
		t.Fatalf("tunneled bytes = %q", got)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
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

func TestWarpNeedsToSAcceptance(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "Cloudflare non-interactive ToS error",
			out:  "Please accept the WARP Terms of Service by running this command in a TTY or by passing the --accept-tos flag.",
			want: true,
		},
		{
			name: "unrelated command error",
			out:  "warp-cli: unknown command status",
			want: false,
		},
		{
			name: "connected status",
			out:  "Status update: Connected\nNetwork: healthy",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := warpNeedsToSAcceptance([]byte(tt.out)); got != tt.want {
				t.Fatalf("warpNeedsToSAcceptance() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRunWarpCLIRetriesWithAcceptTOSWhenSystemdStyleCallIsRejected(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("test helper uses a POSIX shell script")
	}
	warpCLIMu.Lock()
	warpCLIAcceptTOS = false
	warpCLIMu.Unlock()
	t.Cleanup(func() {
		warpCLIMu.Lock()
		warpCLIAcceptTOS = false
		warpCLIMu.Unlock()
	})

	bin := filepath.Join(t.TempDir(), "warp-cli")
	script := `#!/bin/sh
if [ "$1" = "--accept-tos" ]; then
  case "$2" in
    status) printf 'Status update: Connected\nNetwork: healthy\n'; exit 0 ;;
    settings) printf 'WARP tunnel protocol: MASQUE\n'; exit 0 ;;
  esac
fi
printf 'Please accept the WARP Terms of Service by running this command in a TTY or by passing the --accept-tos flag.\n' >&2
exit 1
`
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatalf("write fake warp-cli: %v", err)
	}
	output, err := runWarpCLI(bin, "status")
	if err != nil {
		t.Fatalf("runWarpCLI should retry with --accept-tos, got error %v and output %q", err, output)
	}
	if !warpStatusConnected(string(output)) {
		t.Fatalf("expected connected status after retry, got %q", output)
	}
	settings, err := runWarpCLI(bin, "settings")
	if err != nil {
		t.Fatalf("subsequent WARP CLI calls should remember --accept-tos, got error %v and output %q", err, settings)
	}
	if !warpProtocolMatches(string(settings), "MASQUE") {
		t.Fatalf("expected MASQUE settings after the remembered ToS flag, got %q", settings)
	}
}

func TestBuildXrayWarpConfigIsolatesOnlyClonedInbound(t *testing.T) {
	original := []byte(`{
  "api":{"tag":"api","services":["HandlerService"]},
  "metrics":{"listen":"127.0.0.1:11111"},
  "inbounds": [
    {"tag":"existing-vless","listen":"0.0.0.0","port":2083,"protocol":"vless","settings":{"clients":[{"id":"test-id"}]}}
  ],
  "outbounds": [
    {"tag":"direct","protocol":"freedom"}
  ],
  "routing": {"domainStrategy":"AsIs","rules":[{"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block"}]}
}`)
	originalCopy := append([]byte(nil), original...)
	generated, bindings, outTag, err := buildXrayWarpConfig(original, "warp-profile", "127.0.0.1:40000", []PortMapping{{ID: "main", Target: "127.0.0.1:2083"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, originalCopy) {
		t.Fatal("source X-UI config bytes were mutated")
	}
	if len(bindings) != 1 || bindings[0].OriginalTarget != "127.0.0.1:2083" {
		t.Fatalf("unexpected bindings: %#v", bindings)
	}
	if bindings[0].WarpTarget == bindings[0].OriginalTarget {
		t.Fatal("WARP clone must use a dedicated local port")
	}
	var got map[string]any
	if err := json.Unmarshal(generated, &got); err != nil {
		t.Fatal(err)
	}
	inbounds := got["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("sidecar inbound count=%d; want only the WARP clone", len(inbounds))
	}
	cloneInbound := inbounds[0].(map[string]any)
	if cloneInbound["listen"] != "127.0.0.1" || cloneInbound["tag"] != bindings[0].InboundTag {
		t.Fatalf("clone is not private/tagged: %#v", cloneInbound)
	}
	if _, ok := got["api"]; ok {
		t.Fatal("X-UI API section must not be copied into the isolated sidecar")
	}
	if _, ok := got["metrics"]; ok {
		t.Fatal("metrics listener must not be duplicated by the isolated sidecar")
	}
	outbounds := got["outbounds"].([]any)
	warpFound := false
	directFound := false
	for _, raw := range outbounds {
		x := raw.(map[string]any)
		if x["tag"] == outTag {
			warpFound = true
			if x["protocol"] != "socks" {
				t.Fatalf("WARP outbound protocol=%v", x["protocol"])
			}
		}
		if x["tag"] == "direct" {
			directFound = true
		}
	}
	if !warpFound || !directFound {
		t.Fatalf("sidecar must preserve original outbound set and add WARP outbound: %#v", outbounds)
	}
	rules := got["routing"].(map[string]any)["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["outboundTag"] != outTag {
		t.Fatalf("first routing rule does not target WARP: %#v", first)
	}
	if len(cloneInbound["settings"].(map[string]any)["clients"].([]any)) != 1 {
		t.Fatal("cloned inbound lost original client settings")
	}
}

func TestRenderXrayWarpUnitRunsIndependentSidecar(t *testing.T) {
	runtime := xrayRuntime{Binary: "/usr/local/x-ui/bin/xray-linux-amd64", CWD: "/usr/local/x-ui/bin", Service: "x-ui.service"}
	service := xrayWarpServiceName("profile-s")
	unit, err := renderXrayWarpUnit(runtime, "/etc/ravanreverse/xray-warp/profile-s/config.json", service)
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	for _, want := range []string{
		"ExecStart=\"/usr/local/x-ui/bin/xray-linux-amd64\" run -config \"/etc/ravanreverse/xray-warp/profile-s/config.json\"",
		"WorkingDirectory=\"/usr/local/x-ui/bin\"",
		"Restart=on-failure",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("sidecar unit missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "systemctl restart x-ui") || strings.Contains(text, "x-ui.service") {
		t.Fatalf("sidecar unit must not restart or manage X-UI: %s", text)
	}
	if strings.Contains(text, "ExecStart=/bin/sh") {
		t.Fatal("sidecar unit must execute Xray directly, not through a shell")
	}
}

func TestXrayWarpManagedPathsAreRestricted(t *testing.T) {
	if _, err := xrayWarpUnitPath("x-ui.service"); err == nil {
		t.Fatal("must not manage X-UI systemd unit")
	}
	if _, err := xrayWarpConfigDirectory("/usr/local/x-ui/bin/config.json"); err == nil {
		t.Fatal("must not remove or alter X-UI config directory")
	}
	if dir, err := xrayWarpConfigDirectory("/etc/ravanreverse/xray-warp/profile-s/config.json"); err != nil || dir != "/etc/ravanreverse/xray-warp/profile-s" {
		t.Fatalf("unexpected managed config directory %q, error=%v", dir, err)
	}
}

func TestBuildXrayWarpConfigRejectsNonLoopbackAndAmbiguousInbound(t *testing.T) {
	base := []byte(`{"inbounds":[{"port":2083,"protocol":"vless"}],"outbounds":[{"protocol":"freedom"}]}`)
	if _, _, _, err := buildXrayWarpConfig(base, "p", "127.0.0.1:40000", []PortMapping{{ID: "x", Target: "192.0.2.1:2083"}}); err == nil {
		t.Fatal("non-loopback target must be rejected")
	}
	ambiguous := []byte(`{"inbounds":[{"port":2083,"protocol":"vless"},{"port":2083,"protocol":"vmess"}],"outbounds":[{"protocol":"freedom"}]}`)
	if _, _, _, err := buildXrayWarpConfig(ambiguous, "p", "127.0.0.1:40000", []PortMapping{{ID: "x", Target: "127.0.0.1:2083"}}); err == nil {
		t.Fatal("ambiguous port must be rejected")
	}
}
