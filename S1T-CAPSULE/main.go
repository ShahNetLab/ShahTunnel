package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	version                          = "1.6.2"
	configPath                       = "/etc/ravanreverse/config.json"
	maxFrame                         = 64 * 1024
	defaultTunnelChannels            = 12
	maxPendingPublicConnections      = 2048
	controlBurstLimit                = 8
	streamAdmissionWait              = 5 * time.Second
	maxTunnelChannels                = 16
	msgOpen                     byte = 1
	msgOpenOK                   byte = 2
	msgOpenErr                  byte = 3
	msgData                     byte = 4
	msgClose                    byte = 5
	msgPing                     byte = 6
	msgPong                     byte = 7
	maxStreams                       = 512
	streamWindowFrames               = 8
	maxQueuedPayloadBytes            = int64(64 << 20)
	wireWriteTimeout                 = 30 * time.Second
	reverseStreamOpenTimeout         = 18 * time.Second
	transportAuto                    = "auto"
	transportAdaptive                = "adaptive"
	transportTCP                     = "tcp_tls"
	transportWebSocket               = "websocket_tls"
	transportHTTP2                   = "http2_connect"
	transportHTTP1                   = "http1_connect"
	transportHTTPConnectAuto         = "http_connect_auto"
	http2TokenHeader                 = "X-S1T-Token"
	webSocketPath                    = "/s1t-tunnel"
	webSocketGUID                    = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	maxWebSocketHeaders              = 16 * 1024
	maxWebSocketFrame                = maxFrame + 9
	msgHalfClose                byte = 8
	msgDataAck                  byte = 9
)

var (
	errMaxConcurrentStreams = errors.New("maximum concurrent stream limit reached")
	errHubLaneClosed        = errors.New("tunnel lane is closed")
)

type PortMapping struct {
	ID     string `json:"id"`
	Listen string `json:"listen,omitempty"` // Hub public listener
	Target string `json:"target,omitempty"` // Agent local target
}

type Config struct {
	Version       string `json:"version"`
	Role          string `json:"role"`                // hub on Iran, agent on outside
	Transport     string `json:"transport,omitempty"` // auto, adaptive, tcp_tls, websocket_tls, http2_connect, http1_connect, or http_connect_auto
	ControlListen string `json:"control_listen,omitempty"`
	PublicListen  string `json:"public_listen,omitempty"`
	HubAddr       string `json:"hub_addr,omitempty"`
	TLSServerName string `json:"tls_server_name,omitempty"`
	Target        string `json:"target,omitempty"`
	Token         string `json:"token"`
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	// TunnelChannels controls the number of independent authenticated TCP/TLS lanes
	// between Agent and Hub. Missing values on old configs are upgraded in memory to the current default.
	TunnelChannels int `json:"tunnel_channels,omitempty"`
	// DNSFilterEnabled starts an optional DNS sinkhole for common ad/tracker domains.
	// Clients must explicitly use this resolver; it is not a packet-level VPN filter.
	DNSFilterEnabled      bool          `json:"dns_filter_enabled,omitempty"`
	DNSFilterListen       string        `json:"dns_filter_listen,omitempty"`
	DNSFilterUpstream     string        `json:"dns_filter_upstream,omitempty"`
	DNSFilterAllowedCIDRs []string      `json:"dns_filter_allowed_cidrs,omitempty"`
	Ports                 []PortMapping `json:"ports,omitempty"`
}

type RuntimeSnapshot struct {
	Role              string    `json:"role"`
	Updated           time.Time `json:"updated"`
	Connected         bool      `json:"connected"`
	ActiveConnections int64     `json:"active_connections"`
	TotalConnections  uint64    `json:"total_connections"`
	BytesSent         uint64    `json:"bytes_sent"`
	BytesReceived     uint64    `json:"bytes_received"`
}

var wireFramePool = sync.Pool{New: func() any { return make([]byte, 0, maxFrame+9) }}

var metricActive atomic.Int64
var metricTotal atomic.Uint64
var metricSent atomic.Uint64
var metricReceived atomic.Uint64
var metricConnected atomic.Bool
var lastAuthFailureLog atomic.Int64
var queuedPayloadBytes atomic.Int64
var queuedPayloadChanged = make(chan struct{}, 1)

// The Agent reports connected while at least one parallel tunnel lane is alive.
// A mutex keeps the metric accurate when lanes reconnect concurrently.
var agentMetricMu sync.Mutex
var agentMetricChannels int64

// agentPreferredTransport remembers the last authenticated transport independently per lane.
// It is used only by adaptive mode; legacy auto mode keeps its deterministic TCP-then-WebSocket order.
var agentPreferredTransport sync.Map // map[int]string
var nextHubSessionID atomic.Uint64

// logAuthFailure rate-limits unauthenticated peer logs to reduce journal flooding.
func logAuthFailure(message string) {
	now := time.Now().UnixNano()
	previous := lastAuthFailureLog.Load()
	if now-previous < int64(5*time.Second) {
		return
	}
	if lastAuthFailureLog.CompareAndSwap(previous, now) {
		log.Printf("%s", message)
	}
}

func startMetricsReporter(role string) {
	writeRuntimeStats(role)
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for range t.C {
			writeRuntimeStats(role)
		}
	}()
}
func writeRuntimeStats(role string) {
	s := RuntimeSnapshot{Role: role, Updated: time.Now().UTC(), Connected: metricConnected.Load(), ActiveConnections: metricActive.Load(), TotalConnections: metricTotal.Load(), BytesSent: metricSent.Load(), BytesReceived: metricReceived.Load()}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}
	tmp := "/etc/ravanreverse/runtime.json.tmp"
	if err = os.MkdirAll("/etc/ravanreverse", 0700); err != nil {
		return
	}
	if err = os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, "/etc/ravanreverse/runtime.json")
	_ = os.Chmod("/etc/ravanreverse/runtime.json", 0600)
}

type counterWriter struct {
	w       io.Writer
	counter *atomic.Uint64
}

func (w counterWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		w.counter.Add(uint64(n))
	}
	return n, err
}

// bufferedConn preserves bytes already read by a bufio.Reader during protocol detection.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// websocketConn exposes WebSocket binary messages as a net.Conn stream. The
// tunnel remains protected by TLS 1.3; extensions and fragmentation are not negotiated.
type websocketConn struct {
	net.Conn
	r          *bufio.Reader
	clientSide bool
	readMu     sync.Mutex
	writeMu    sync.Mutex
	readBuf    []byte
}

func (c *websocketConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.readBuf) == 0 {
		op, payload, err := c.readFrame()
		if err != nil {
			return 0, err
		}
		switch op {
		case 0x2:
			c.readBuf = payload
		case 0x9:
			if err := c.writeControl(0xA, payload); err != nil {
				return 0, err
			}
		case 0xA:
			continue
		case 0x8:
			_ = c.writeControl(0x8, payload)
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unsupported WebSocket opcode %d", op)
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *websocketConn) readFrame() (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		return 0, nil, err
	}
	if h[0]&0x70 != 0 || h[0]&0x80 == 0 {
		return 0, nil, errors.New("fragmented or reserved WebSocket frame rejected")
	}
	op := h[0] & 0x0f
	masked := h[1]&0x80 != 0
	if masked != !c.clientSide {
		return 0, nil, errors.New("invalid WebSocket masking direction")
	}
	length := uint64(h[1] & 0x7f)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(c.r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
		if length < 126 {
			return 0, nil, errors.New("non-canonical WebSocket payload length")
		}
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(c.r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length < 65536 || length>>63 != 0 {
			return 0, nil, errors.New("invalid WebSocket payload length")
		}
	}
	if length > maxWebSocketFrame {
		return 0, nil, fmt.Errorf("WebSocket frame too large: %d", length)
	}
	if op >= 0x8 && length > 125 {
		return 0, nil, errors.New("invalid WebSocket control frame length")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.r, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if length != 0 {
		if _, err := io.ReadFull(c.r, payload); err != nil {
			return 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return op, payload, nil
}

func (c *websocketConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxWebSocketFrame {
			n = maxWebSocketFrame
		}
		if err := c.writeFrameUnlocked(0x2, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *websocketConn) writeControl(op byte, p []byte) error {
	if len(p) > 125 {
		return errors.New("WebSocket control payload exceeds 125 bytes")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrameUnlocked(op, p)
}

func (c *websocketConn) writeFrameUnlocked(op byte, p []byte) error {
	if len(p) > maxWebSocketFrame {
		return fmt.Errorf("WebSocket frame too large: %d", len(p))
	}
	masked := c.clientSide
	var header [14]byte
	i := 0
	header[i] = 0x80 | (op & 0x0f)
	i++
	maskFlag := byte(0)
	if masked {
		maskFlag = 0x80
	}
	switch {
	case len(p) < 126:
		header[i] = maskFlag | byte(len(p))
		i++
	case len(p) <= 65535:
		header[i] = maskFlag | 126
		i++
		binary.BigEndian.PutUint16(header[i:i+2], uint16(len(p)))
		i += 2
	default:
		header[i] = maskFlag | 127
		i++
		binary.BigEndian.PutUint64(header[i:i+8], uint64(len(p)))
		i += 8
	}
	payload := p
	if masked {
		var mask [4]byte
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		copy(header[i:i+4], mask[:])
		i += 4
		payload = make([]byte, len(p))
		for n := range p {
			payload[n] = p[n] ^ mask[n&3]
		}
	}
	if err := writeFull(c.Conn, header[:i]); err != nil {
		return err
	}
	if len(payload) > 0 {
		return writeFull(c.Conn, payload)
	}
	return nil
}

func readWebSocketHTTPLine(r *bufio.Reader, total *int) (string, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errors.New("WebSocket HTTP header line too large")
	}
	if err != nil {
		return "", err
	}
	*total += len(line)
	if *total > maxWebSocketHeaders {
		return "", errors.New("WebSocket HTTP headers too large")
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", errors.New("malformed WebSocket HTTP line ending")
	}
	return string(line[:len(line)-2]), nil
}

func readWebSocketHTTPHeaders(r *bufio.Reader) (string, map[string]string, error) {
	total := 0
	start, err := readWebSocketHTTPLine(r, &total)
	if err != nil {
		return "", nil, err
	}
	headers := make(map[string]string)
	for {
		line, e := readWebSocketHTTPLine(r, &total)
		if e != nil {
			return "", nil, e
		}
		if line == "" {
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			return "", nil, errors.New("malformed WebSocket HTTP header")
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		if key == "" || strings.ContainsAny(key, " \t") {
			return "", nil, errors.New("invalid WebSocket HTTP header name")
		}
		if _, exists := headers[key]; exists {
			return "", nil, fmt.Errorf("duplicate WebSocket HTTP header %q", key)
		}
		headers[key] = value
	}
	return start, headers, nil
}

func hasHTTPToken(value, token string) bool {
	for _, item := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(item), token) {
			return true
		}
	}
	return false
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + webSocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func acceptWebSocketUpgrade(conn net.Conn, r *bufio.Reader) error {
	start, h, err := readWebSocketHTTPHeaders(r)
	if err != nil {
		return err
	}
	parts := strings.Fields(start)
	if len(parts) != 3 || parts[0] != "GET" || parts[1] != webSocketPath || parts[2] != "HTTP/1.1" {
		return errors.New("invalid WebSocket upgrade request line")
	}
	if h["host"] == "" || !strings.EqualFold(h["upgrade"], "websocket") || !hasHTTPToken(h["connection"], "upgrade") || h["sec-websocket-version"] != "13" {
		return errors.New("incomplete WebSocket upgrade request")
	}
	if h["sec-websocket-extensions"] != "" {
		return errors.New("WebSocket extensions are not supported")
	}
	key := h["sec-websocket-key"]
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		return errors.New("invalid WebSocket client key")
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + websocketAccept(key) + "\r\n\r\n"
	return writeFull(conn, []byte(response))
}

func clientWebSocketUpgrade(conn net.Conn, host string) (net.Conn, error) {
	if strings.TrimSpace(host) == "" || strings.ContainsAny(host, "\r\n") {
		return nil, errors.New("invalid WebSocket Host header")
	}
	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])
	request := "GET " + webSocketPath + " HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if err := writeFull(conn, []byte(request)); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, maxWebSocketHeaders)
	start, h, err := readWebSocketHTTPHeaders(r)
	if err != nil {
		return nil, fmt.Errorf("read WebSocket upgrade response: %w", err)
	}
	parts := strings.Fields(start)
	if len(parts) < 2 || parts[0] != "HTTP/1.1" || parts[1] != "101" || !strings.EqualFold(h["upgrade"], "websocket") || !hasHTTPToken(h["connection"], "upgrade") || h["sec-websocket-accept"] != websocketAccept(key) {
		return nil, errors.New("Hub rejected WebSocket upgrade")
	}
	return &websocketConn{Conn: conn, r: r, clientSide: true}, nil
}

func validTransportMode(mode string) bool {
	return mode == transportAuto || mode == transportAdaptive || mode == transportTCP || mode == transportWebSocket || mode == transportHTTP2 || mode == transportHTTP1 || mode == transportHTTPConnectAuto
}
func transportAllowed(configured, observed string) bool {
	return configured == transportAuto || configured == transportAdaptive || configured == observed || (configured == transportHTTPConnectAuto && (observed == transportHTTP2 || observed == transportHTTP1))
}

type frame struct {
	typ  byte
	id   uint32
	data []byte
}

type wireRequest struct {
	typ  byte
	id   uint32
	data []byte
	done chan error
}

type wire struct {
	conn       net.Conn
	controlQ   chan *wireRequest
	dataQ      chan *wireRequest
	done       chan struct{}
	once       sync.Once
	rttNanos   atomic.Int64 // EWMA of authenticated PING/PONG round-trip time; zero until measured.
	lastPongAt atomic.Int64 // Unix nanoseconds of the latest valid PONG, for diagnostics/future health checks.
}

func newWire(c net.Conn) *wire {
	tuneTCPConn(c)
	w := &wire{
		conn: c,
		// Control traffic (OPEN/ACK/CLOSE/PING) must not queue behind
		// bulk payloads. Data remains bounded so a slow path applies backpressure.
		controlQ: make(chan *wireRequest, 256),
		dataQ:    make(chan *wireRequest, 64),
		done:     make(chan struct{}),
	}
	go w.writeLoop()
	return w
}

// tuneTCPConn applies latency-safe options without disabling Linux TCP
// autotuning or forcing oversized per-socket buffers. It also works with a
// tls.Conn by tuning the underlying TCP socket.
func tuneTCPConn(c net.Conn) {
	if c == nil {
		return
	}
	raw := c
	switch wrapped := c.(type) {
	case *tls.Conn:
		raw = wrapped.NetConn()
	case *websocketConn:
		raw = wrapped.Conn
	case *bufferedConn:
		raw = wrapped.Conn
	}
	if tc, ok := raw.(*tls.Conn); ok {
		raw = tc.NetConn()
	}
	tcp, ok := raw.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tcp.SetNoDelay(true)
	_ = tcp.SetKeepAlive(true)
	_ = tcp.SetKeepAlivePeriod(30 * time.Second)
}

func adjustAgentChannels(delta int64) {
	agentMetricMu.Lock()
	agentMetricChannels += delta
	if agentMetricChannels < 0 {
		agentMetricChannels = 0
	}
	metricConnected.Store(agentMetricChannels > 0)
	agentMetricMu.Unlock()
}
func (w *wire) close() { w.once.Do(func() { close(w.done); _ = w.conn.Close() }) }
func (w *wire) send(typ byte, id uint32, data []byte) error {
	if len(data) > maxFrame {
		return fmt.Errorf("frame too large: %d", len(data))
	}
	select {
	case <-w.done:
		return net.ErrClosed
	default:
	}
	req := &wireRequest{typ: typ, id: id, data: data, done: make(chan error, 1)}
	queue := w.controlQ
	if typ == msgData {
		queue = w.dataQ
	}
	// send stays synchronous: callers may safely reuse their frame buffer only
	// after this returns. Queueing is bounded and cancellation follows lane close.
	select {
	case queue <- req:
	case <-w.done:
		return net.ErrClosed
	}
	select {
	case err := <-req.done:
		return err
	case <-w.done:
		return net.ErrClosed
	}
}

func (w *wire) writeRequest(req *wireRequest) error {
	_ = w.conn.SetWriteDeadline(time.Now().Add(wireWriteTimeout))
	buf := wireFramePool.Get().([]byte)[:9+len(req.data)]
	buf[0] = req.typ
	binary.BigEndian.PutUint32(buf[1:5], req.id)
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(req.data)))
	copy(buf[9:], req.data)
	err := writeFull(w.conn, buf)
	wireFramePool.Put(buf[:0])
	_ = w.conn.SetWriteDeadline(time.Time{})
	return err
}

func (w *wire) writeLoop() {
	controlStreak := 0
	for {
		var req *wireRequest
		// Prefer control traffic, but cap consecutive control frames when payload
		// is already queued. Without this bound a stream of ACK/PING frames can
		// starve user payload and cause avoidable latency spikes under concurrency.
		if controlStreak < controlBurstLimit {
			select {
			case <-w.done:
				return
			case req = <-w.controlQ:
				controlStreak++
			default:
			}
		}
		if req == nil {
			// At the burst limit, take payload immediately if any is waiting.
			select {
			case req = <-w.dataQ:
				controlStreak = 0
			default:
			}
		}
		if req == nil {
			select {
			case <-w.done:
				return
			case req = <-w.dataQ:
				controlStreak = 0
			case req = <-w.controlQ:
				controlStreak++
			}
		}
		if req == nil {
			continue
		}
		if err := w.writeRequest(req); err != nil {
			// Deliver the concrete error to the current sender before closing the
			// lane; all other queued senders unblock through w.done.
			req.done <- err
			w.close()
			return
		}
		req.done <- nil
	}
}
func (w *wire) receive() (frame, error) {
	var h [9]byte
	if _, err := io.ReadFull(w.conn, h[:]); err != nil {
		return frame{}, err
	}
	n := binary.BigEndian.Uint32(h[5:9])
	if n > maxFrame {
		return frame{}, fmt.Errorf("peer sent oversized frame: %d", n)
	}
	f := frame{typ: h[0], id: binary.BigEndian.Uint32(h[1:5])}
	if n > 0 {
		f.data = make([]byte, int(n))
		if _, err := io.ReadFull(w.conn, f.data); err != nil {
			return frame{}, err
		}
	}
	return f, nil
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

type streamWriteRequest struct {
	data      []byte
	halfClose bool
}

// streamWriter isolates a slow local destination from the shared frame reader.
// Data is acknowledged only after it has been written to the destination, which
// provides per-stream back-pressure. The bounded queue and global byte budget
// keep a slow target from consuming unbounded RAM.
type streamWriter struct {
	conn        net.Conn
	queue       chan streamWriteRequest
	done        chan struct{}
	mu          sync.Mutex
	closed      bool
	onWritten   func() error
	onHalfClose func()
	onError     func(error)
}

func reserveQueuedPayload(n int) bool {
	if n < 0 || int64(n) > maxQueuedPayloadBytes {
		return false
	}
	for {
		old := queuedPayloadBytes.Load()
		if old+int64(n) > maxQueuedPayloadBytes {
			return false
		}
		if queuedPayloadBytes.CompareAndSwap(old, old+int64(n)) {
			return true
		}
	}
}

// reserveQueuedPayloadWait applies back-pressure when the process-wide queue
// budget is full instead of dropping a healthy stream. The retry timeout makes
// waiters resilient to coalesced notifications and missed wake-up races.
func reserveQueuedPayloadWait(n int, done <-chan struct{}) bool {
	if n < 0 || int64(n) > maxQueuedPayloadBytes {
		return false
	}
	for {
		if reserveQueuedPayload(n) {
			return true
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return false
		case <-queuedPayloadChanged:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
	}
}

func releaseQueuedPayload(n int) {
	if n <= 0 {
		return
	}
	queuedPayloadBytes.Add(-int64(n))
	select {
	case queuedPayloadChanged <- struct{}{}:
	default:
	}
}

func newStreamWriter(conn net.Conn, onWritten func() error, onHalfClose func(), onError func(error)) *streamWriter {
	w := &streamWriter{
		conn: conn, queue: make(chan streamWriteRequest, streamWindowFrames+1),
		done: make(chan struct{}), onWritten: onWritten, onHalfClose: onHalfClose, onError: onError,
	}
	go w.run()
	return w
}

func (w *streamWriter) enqueue(data []byte) bool {
	if !reserveQueuedPayloadWait(len(data), w.done) {
		return false
	}
	request := streamWriteRequest{data: data}
	for {
		w.mu.Lock()
		if w.closed {
			w.mu.Unlock()
			releaseQueuedPayload(len(data))
			return false
		}
		select {
		case w.queue <- request:
			w.mu.Unlock()
			return true
		default:
			w.mu.Unlock()
		}
		// The per-stream writer drains this bounded queue independently. Wait for
		// room without holding the mutex needed by close() or the writer goroutine.
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-w.done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			releaseQueuedPayload(len(data))
			return false
		case <-timer.C:
		}
	}
}

func (w *streamWriter) enqueueHalfClose() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	select {
	case w.queue <- streamWriteRequest{halfClose: true}:
		return true
	default:
		return false
	}
}

func (w *streamWriter) close() {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.done)
		_ = w.conn.Close()
	}
	w.mu.Unlock()
}

func (w *streamWriter) drain() {
	for {
		select {
		case req := <-w.queue:
			if len(req.data) > 0 {
				releaseQueuedPayload(len(req.data))
			}
		default:
			return
		}
	}
}

func (w *streamWriter) fail(err error) {
	if w.onError != nil {
		w.onError(err)
	}
	w.close()
	w.drain()
}

func (w *streamWriter) run() {
	for {
		select {
		case <-w.done:
			w.drain()
			return
		case req := <-w.queue:
			if req.halfClose {
				cw, ok := w.conn.(interface{ CloseWrite() error })
				if !ok {
					w.fail(errors.New("stream does not support TCP half-close"))
					return
				}
				if err := cw.CloseWrite(); err != nil {
					w.fail(err)
					return
				}
				if w.onHalfClose != nil {
					w.onHalfClose()
				}
				continue
			}
			_ = w.conn.SetWriteDeadline(time.Now().Add(45 * time.Second))
			err := writeFull(w.conn, req.data)
			_ = w.conn.SetWriteDeadline(time.Time{})
			releaseQueuedPayload(len(req.data))
			if err == nil && w.onWritten != nil {
				err = w.onWritten()
			}
			if err != nil {
				w.fail(err)
				return
			}
		}
	}
}

type streamEOF struct{ flags atomic.Uint32 }

func (e *streamEOF) mark(local bool) bool {
	var bit uint32 = 2
	if local {
		bit = 1
	}
	for {
		old := e.flags.Load()
		next := old | bit
		if e.flags.CompareAndSwap(old, next) {
			return next == 3
		}
	}
}

func acknowledge(ch chan struct{}) {
	select {
	case <-ch:
	default:
	}
}

func heartbeat(w *wire, stop <-chan struct{}) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-w.done:
			return
		case <-t.C:
			// The timestamp is echoed by compatible peers. Older peers ignore the
			// payload and return an empty PONG, so this enhancement is wire-compatible.
			var payload [8]byte
			binary.BigEndian.PutUint64(payload[:], uint64(time.Now().UnixNano()))
			if err := w.send(msgPing, 0, payload[:]); err != nil {
				w.close()
				return
			}
		}
	}
}

// observePong records the round-trip time encoded by our own PING timestamp.
// A wall-clock adjustment or malformed/stale payload is ignored instead of
// poisoning lane selection. The 1/8 EWMA dampens transient scheduling spikes.
func (w *wire) observePong(payload []byte) {
	if len(payload) != 8 {
		return
	}
	sentAt := int64(binary.BigEndian.Uint64(payload))
	now := time.Now().UnixNano()
	elapsed := now - sentAt
	if elapsed <= 0 || elapsed > int64(2*time.Minute) {
		return
	}
	for {
		old := w.rttNanos.Load()
		var next int64
		if old <= 0 {
			next = elapsed
		} else {
			next = (old*7 + elapsed) / 8
		}
		if w.rttNanos.CompareAndSwap(old, next) {
			w.lastPongAt.Store(now)
			return
		}
	}
}

func (w *wire) roundTripTime() time.Duration {
	if w == nil {
		return 0
	}
	n := w.rttNanos.Load()
	if n <= 0 {
		return 0
	}
	return time.Duration(n)
}

type hubStream struct {
	conn       net.Conn
	opened     chan error
	openedOnce sync.Once
	writer     *streamWriter
	inflight   chan struct{}
	eof        streamEOF
}

func (s *hubStream) reportOpen(err error) { s.openedOnce.Do(func() { s.opened <- err }) }
func (s *hubStream) close() {
	if s.writer != nil {
		s.writer.close()
	} else {
		_ = s.conn.Close()
	}
}

type hubSession struct {
	id       uint64
	wire     *wire
	mu       sync.RWMutex
	streams  map[uint32]*hubStream
	next     atomic.Uint32
	stopOnce sync.Once
}

func newHubSession(c net.Conn) *hubSession {
	return &hubSession{id: nextHubSessionID.Add(1), wire: newWire(c), streams: make(map[uint32]*hubStream)}
}

func (s *hubSession) activeStreams() int {
	s.mu.RLock()
	n := len(s.streams)
	s.mu.RUnlock()
	return n
}
func (s *hubSession) get(id uint32) *hubStream {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.streams[id]
}
func (s *hubSession) remove(id uint32, closeConn bool) *hubStream {
	s.mu.Lock()
	st := s.streams[id]
	delete(s.streams, id)
	s.mu.Unlock()
	if st != nil {
		metricActive.Add(-1)
	}
	if st != nil && closeConn {
		st.close()
		st.reportOpen(errors.New("stream closed"))
	}
	return st
}
func (s *hubSession) shutdown() {
	s.stopOnce.Do(func() {
		s.wire.close()
		s.mu.Lock()
		for id, st := range s.streams {
			st.close()
			st.reportOpen(net.ErrClosed)
			delete(s.streams, id)
			metricActive.Add(-1)
		}
		s.mu.Unlock()
	})
}
func (s *hubSession) addStream(c net.Conn, portID ...string) (uint32, *hubStream, error) {
	key := "main"
	if len(portID) > 0 && strings.TrimSpace(portID[0]) != "" {
		key = portID[0]
	}
	id := s.next.Add(1)
	if id == 0 {
		id = s.next.Add(1)
	}
	st := &hubStream{conn: c, opened: make(chan error, 1), inflight: make(chan struct{}, streamWindowFrames)}
	s.mu.Lock()
	select {
	case <-s.wire.done:
		s.mu.Unlock()
		return 0, nil, errHubLaneClosed
	default:
	}
	if len(s.streams) >= maxStreams {
		s.mu.Unlock()
		return 0, nil, errMaxConcurrentStreams
	}
	st.writer = newStreamWriter(c,
		func() error { return s.wire.send(msgDataAck, id, nil) },
		func() {
			if st.eof.mark(false) {
				s.remove(id, true)
			}
		},
		func(err error) {
			if s.remove(id, true) != nil {
				_ = s.wire.send(msgClose, id, nil)
			}
		},
	)
	s.streams[id] = st
	metricActive.Add(1)
	metricTotal.Add(1)
	s.mu.Unlock()
	if err := s.wire.send(msgOpen, id, []byte(key)); err != nil {
		s.remove(id, true)
		return 0, nil, err
	}
	select {
	case err := <-st.opened:
		if err != nil {
			s.remove(id, true)
			return 0, nil, err
		}
	case <-time.After(reverseStreamOpenTimeout):
		s.remove(id, true)
		_ = s.wire.send(msgClose, id, nil)
		return 0, nil, fmt.Errorf("agent did not acknowledge mapping %q within %s", key, reverseStreamOpenTimeout)
	case <-s.wire.done:
		s.remove(id, true)
		return 0, nil, net.ErrClosed
	}
	go s.pumpPublicToAgent(id, st)
	return id, st, nil
}
func (s *hubSession) pumpPublicToAgent(id uint32, st *hubStream) {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := st.conn.Read(buf)
		if n > 0 {
			select {
			case st.inflight <- struct{}{}:
			case <-st.writer.done:
				return
			}
			if err := s.wire.send(msgData, id, buf[:n]); err != nil {
				acknowledge(st.inflight)
				s.remove(id, true)
				return
			}
			metricSent.Add(uint64(n))
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := s.wire.send(msgHalfClose, id, nil); err != nil {
					s.remove(id, true)
					return
				}
				if st.eof.mark(true) {
					s.remove(id, true)
				}
				return
			}
			_ = s.wire.send(msgClose, id, nil)
			s.remove(id, true)
			return
		}
	}
}

func (s *hubSession) run() {
	defer s.shutdown()
	stop := make(chan struct{})
	defer close(stop)
	go heartbeat(s.wire, stop)
	for {
		_ = s.wire.conn.SetReadDeadline(time.Now().Add(50 * time.Second))
		f, err := s.wire.receive()
		if err != nil {
			log.Printf("reverse agent session ended (connection closed or timed out)")
			return
		}
		st := s.get(f.id)
		switch f.typ {
		case msgOpenOK:
			if st != nil {
				st.reportOpen(nil)
			}
		case msgOpenErr:
			if st != nil {
				msg := strings.TrimSpace(string(f.data))
				if len(msg) > 200 {
					msg = msg[:200]
				}
				st.reportOpen(fmt.Errorf("outside target open failed: %s", msg))
			}
		case msgData:
			if st != nil {
				if !st.writer.enqueue(f.data) {
					if s.remove(f.id, true) != nil {
						_ = s.wire.send(msgClose, f.id, nil)
					}
				} else {
					metricReceived.Add(uint64(len(f.data)))
				}
			}
		case msgDataAck:
			if st != nil {
				acknowledge(st.inflight)
			}
		case msgHalfClose:
			if st != nil && !st.writer.enqueueHalfClose() {
				if s.remove(f.id, true) != nil {
					_ = s.wire.send(msgClose, f.id, nil)
				}
			}
		case msgClose:
			s.remove(f.id, true)
		case msgPing:
			// Echo an optional timestamp for RTT measurement. Empty PINGs from
			// older protocol-compatible peers continue to receive an empty PONG.
			payload := f.data
			if len(payload) != 8 {
				payload = nil
			}
			if err := s.wire.send(msgPong, 0, payload); err != nil {
				return
			}
		case msgPong:
			s.wire.observePong(f.data)
		default:
			return
		}
	}
}

type agentStream struct {
	conn     net.Conn
	once     sync.Once
	writer   *streamWriter
	inflight chan struct{}
	eof      streamEOF
}

func (s *agentStream) close() {
	s.once.Do(func() {
		if s.writer != nil {
			s.writer.close()
		} else {
			_ = s.conn.Close()
		}
	})
}

type agentSession struct {
	wire     *wire
	targets  map[string]string
	mu       sync.RWMutex
	streams  map[uint32]*agentStream
	pending  map[uint32]context.CancelFunc
	stopOnce sync.Once
}

func newAgentSession(c net.Conn, targets map[string]string) *agentSession {
	cp := make(map[string]string, len(targets))
	for k, v := range targets {
		cp[k] = v
	}
	return &agentSession{wire: newWire(c), targets: cp, streams: make(map[uint32]*agentStream), pending: make(map[uint32]context.CancelFunc)}
}
func (s *agentSession) get(id uint32) *agentStream {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.streams[id]
}
func (s *agentSession) remove(id uint32, closeConn bool) *agentStream {
	s.mu.Lock()
	if cancel, ok := s.pending[id]; ok {
		delete(s.pending, id)
		cancel()
	}
	st := s.streams[id]
	delete(s.streams, id)
	s.mu.Unlock()
	if st != nil {
		metricActive.Add(-1)
	}
	if st != nil && closeConn {
		st.close()
	}
	return st
}
func (s *agentSession) shutdown() {
	s.stopOnce.Do(func() {
		s.wire.close()
		s.mu.Lock()
		for id, cancel := range s.pending {
			cancel()
			delete(s.pending, id)
		}
		for id, st := range s.streams {
			st.close()
			delete(s.streams, id)
			metricActive.Add(-1)
		}
		s.mu.Unlock()
	})
}

// startOpenTarget reserves capacity before dialing. This bounds concurrent
// pending connects as well as established streams and lets CLOSE cancel a dial.
func (s *agentSession) startOpenTarget(id uint32, key string) {
	s.mu.Lock()
	if _, exists := s.streams[id]; exists {
		s.mu.Unlock()
		_ = s.wire.send(msgOpenErr, id, []byte("duplicate stream id"))
		return
	}
	if _, exists := s.pending[id]; exists {
		s.mu.Unlock()
		_ = s.wire.send(msgOpenErr, id, []byte("duplicate stream id"))
		return
	}
	if len(s.streams)+len(s.pending) >= maxStreams {
		s.mu.Unlock()
		_ = s.wire.send(msgOpenErr, id, []byte(errMaxConcurrentStreams.Error()))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.pending[id] = cancel
	s.mu.Unlock()
	go s.openTarget(ctx, id, key)
}

func (s *agentSession) finishPending(id uint32) {
	s.mu.Lock()
	if cancel, ok := s.pending[id]; ok {
		delete(s.pending, id)
		cancel()
	}
	s.mu.Unlock()
}

func (s *agentSession) openTarget(ctx context.Context, id uint32, key string) {
	defer s.finishPending(id)
	target, ok := s.targets[key]
	if !ok {
		_ = s.wire.send(msgOpenErr, id, []byte("unknown port mapping"))
		return
	}
	var c net.Conn
	var err error
	// A short bounded retry absorbs brief local-service restarts. The context is
	// cancelled when the Hub closes the public stream or the lane shuts down.
	backoffs := [...]time.Duration{150 * time.Millisecond, 350 * time.Millisecond, 700 * time.Millisecond}
	for attempt := 0; attempt < 4; attempt++ {
		dialer := net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
		c, err = dialer.DialContext(ctx, "tcp", target)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return
		}
		if attempt < len(backoffs) {
			timer := time.NewTimer(backoffs[attempt])
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-timer.C:
			}
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		log.Printf("local target unavailable for mapping %q after bounded retries (details suppressed)", key)
		_ = s.wire.send(msgOpenErr, id, []byte("local target unavailable"))
		return
	}
	tuneTCPConn(c)
	st := &agentStream{conn: c, inflight: make(chan struct{}, streamWindowFrames)}
	st.writer = newStreamWriter(c,
		func() error { return s.wire.send(msgDataAck, id, nil) },
		func() {
			if st.eof.mark(false) {
				s.remove(id, true)
			}
		},
		func(err error) {
			if s.remove(id, true) != nil {
				_ = s.wire.send(msgClose, id, nil)
			}
		},
	)
	s.mu.Lock()
	select {
	case <-s.wire.done:
		s.mu.Unlock()
		st.close()
		return
	default:
	}
	if _, pending := s.pending[id]; !pending || ctx.Err() != nil {
		s.mu.Unlock()
		st.close()
		return
	}
	if len(s.streams) >= maxStreams {
		s.mu.Unlock()
		st.close()
		_ = s.wire.send(msgOpenErr, id, []byte(errMaxConcurrentStreams.Error()))
		return
	}
	cancel := s.pending[id]
	delete(s.pending, id)
	s.streams[id] = st
	metricActive.Add(1)
	metricTotal.Add(1)
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if err := s.wire.send(msgOpenOK, id, nil); err != nil {
		s.remove(id, true)
		return
	}
	go s.pumpTargetToHub(id, st)
}
func (s *agentSession) pumpTargetToHub(id uint32, st *agentStream) {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := st.conn.Read(buf)
		if n > 0 {
			select {
			case st.inflight <- struct{}{}:
			case <-st.writer.done:
				return
			}
			if err := s.wire.send(msgData, id, buf[:n]); err != nil {
				acknowledge(st.inflight)
				s.remove(id, true)
				return
			}
			metricSent.Add(uint64(n))
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if err := s.wire.send(msgHalfClose, id, nil); err != nil {
					s.remove(id, true)
					return
				}
				if st.eof.mark(true) {
					s.remove(id, true)
				}
				return
			}
			_ = s.wire.send(msgClose, id, nil)
			s.remove(id, true)
			return
		}
	}
}

func (s *agentSession) run() {
	defer s.shutdown()
	stop := make(chan struct{})
	defer close(stop)
	go heartbeat(s.wire, stop)
	for {
		_ = s.wire.conn.SetReadDeadline(time.Now().Add(50 * time.Second))
		f, err := s.wire.receive()
		if err != nil {
			return
		}
		switch f.typ {
		case msgOpen:
			s.startOpenTarget(f.id, string(f.data))
		case msgData:
			st := s.get(f.id)
			if st != nil {
				if !st.writer.enqueue(f.data) {
					if s.remove(f.id, true) != nil {
						_ = s.wire.send(msgClose, f.id, nil)
					}
				} else {
					metricReceived.Add(uint64(len(f.data)))
				}
			}
		case msgDataAck:
			st := s.get(f.id)
			if st != nil {
				acknowledge(st.inflight)
			}
		case msgHalfClose:
			st := s.get(f.id)
			if st != nil && !st.writer.enqueueHalfClose() {
				if s.remove(f.id, true) != nil {
					_ = s.wire.send(msgClose, f.id, nil)
				}
			}
		case msgClose:
			s.remove(f.id, true)
		case msgPing:
			// Echo an optional timestamp for RTT measurement. Empty PINGs from
			// older protocol-compatible peers continue to receive an empty PONG.
			payload := f.data
			if len(payload) != 8 {
				payload = nil
			}
			if err := s.wire.send(msgPong, 0, payload); err != nil {
				return
			}
		case msgPong:
			s.wire.observePong(f.data)
		default:
			return
		}
	}
}

type hubServer struct {
	cfg           Config
	mu            sync.RWMutex
	sessions      map[*hubSession]struct{}
	pendingPublic chan struct{}
	pickCursor    atomic.Uint64
}

// registerSession keeps every authenticated Agent lane alive independently.
// The previous implementation replaced the old session whenever a new Agent
// connected, making parallel data channels impossible.
func (h *hubServer) registerSession(s *hubSession) {
	h.mu.Lock()
	if h.sessions == nil {
		h.sessions = make(map[*hubSession]struct{})
	}
	h.sessions[s] = struct{}{}
	metricConnected.Store(len(h.sessions) > 0)
	h.mu.Unlock()
}

func (h *hubServer) unregisterSession(s *hubSession) {
	h.mu.Lock()
	delete(h.sessions, s)
	metricConnected.Store(len(h.sessions) > 0)
	h.mu.Unlock()
}

func (h *hubServer) sessionCount() int {
	h.mu.RLock()
	n := len(h.sessions)
	h.mu.RUnlock()
	return n
}

// current chooses the least-loaded healthy lane. When several lanes have the
// same load and all have measured RTT, the lowest-RTT lane wins; a rotating
// tie-breaker prevents pinning every new flow to one connection. RTT is only a
// tie-breaker, not a promise that the lowest-latency lane has the highest capacity.
func (h *hubServer) current() *hubSession {
	h.mu.RLock()
	candidates := make([]*hubSession, 0, len(h.sessions))
	for s := range h.sessions {
		candidates = append(candidates, s)
	}
	h.mu.RUnlock()
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].id < candidates[j].id })
	start := int((h.pickCursor.Add(1) - 1) % uint64(len(candidates)))
	ordered := make([]*hubSession, 0, len(candidates))
	for i := 0; i < len(candidates); i++ {
		ordered = append(ordered, candidates[(start+i)%len(candidates)])
	}

	bestLoad := maxStreams + 1
	var leastLoaded []*hubSession
	for _, candidate := range ordered {
		load := candidate.activeStreams()
		if load >= maxStreams {
			continue
		}
		if load < bestLoad {
			bestLoad = load
			leastLoaded = leastLoaded[:0]
		}
		if load == bestLoad {
			leastLoaded = append(leastLoaded, candidate)
		}
	}
	if len(leastLoaded) == 0 {
		return nil
	}
	if len(leastLoaded) == 1 {
		return leastLoaded[0]
	}

	// Do not prefer an unmeasured lane over a measured one (or vice versa):
	// keep round-robin behaviour until every equally loaded candidate has RTT.
	bestRTT := time.Duration(0)
	for _, candidate := range leastLoaded {
		rtt := candidate.wire.roundTripTime()
		if rtt <= 0 {
			return leastLoaded[0]
		}
		if bestRTT == 0 || rtt < bestRTT {
			bestRTT = rtt
		}
	}
	for _, candidate := range leastLoaded {
		if candidate.wire.roundTripTime() == bestRTT {
			return candidate
		}
	}
	return leastLoaded[0]
}
func (h *hubServer) acceptPublic(ln net.Listener, portID string) {
	pending := h.pendingPublic
	if pending == nil {
		// runHub initializes this shared semaphore before starting listeners. Keep
		// standalone callers safe as well, without introducing a nil-channel block.
		pending = make(chan struct{}, maxPendingPublicConnections)
	}
	acceptErrors := 0
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if isRetryableAcceptError(err) {
				acceptErrors++
				if acceptErrors == 1 {
					log.Printf("temporary public listener accept error; backing off: %v", err)
				}
				time.Sleep(acceptRetryDelay(acceptErrors - 1))
				continue
			}
			log.Printf("public listener stopped after accept error: %v", err)
			return
		}
		acceptErrors = 0
		tuneTCPConn(c)
		select {
		case pending <- struct{}{}:
		default:
			// Bound accepted-but-not-yet-forwarded sockets during traffic bursts.
			_ = c.Close()
			continue
		}
		go func() {
			defer func() { <-pending }()
			if _, _, err := h.openStream(c, portID); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					log.Printf("open reverse stream: %v", err)
				}
				_ = c.Close()
			}
		}()
	}
}

// openStream waits briefly for a lane to recover and retries only pre-allocation
// errors. It never retries after a stream has been allocated, because that path
// may already have closed the public connection.
func (h *hubServer) openStream(c net.Conn, portID string) (uint32, *hubStream, error) {
	var lastErr error
	deadline := time.Now().Add(streamAdmissionWait)
	for time.Now().Before(deadline) {
		s := h.current()
		if s == nil {
			lastErr = net.ErrClosed
			time.Sleep(100 * time.Millisecond)
			continue
		}
		id, st, err := s.addStream(c, portID)
		if err == nil {
			return id, st, nil
		}
		lastErr = err
		if errors.Is(err, errMaxConcurrentStreams) || errors.Is(err, errHubLaneClosed) {
			time.Sleep(25 * time.Millisecond)
			continue
		}
		return 0, nil, err
	}
	if lastErr == nil {
		lastErr = net.ErrClosed
	}
	return 0, nil, lastErr
}

// adjacentPortAddress reserves the TCP port immediately after the native control
// port for the HTTP/2 CONNECT listener. Keeping H2 on a distinct port lets the
// legacy raw TLS and WebSocket/TLS protocols retain their existing wire format.
func offsetPortAddress(addr string, offset int) (string, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", fmt.Errorf("expected host:port: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || offset < 0 || port+offset > 65535 {
		return "", fmt.Errorf("control port must be in range 1–%d to reserve %d additional port(s)", 65535-offset, offset)
	}
	return net.JoinHostPort(host, strconv.Itoa(port+offset)), nil
}

// adjacentPortAddress reserves TCP control port + 1 for HTTP/2 CONNECT.
func adjacentPortAddress(addr string) (string, error) { return offsetPortAddress(addr, 1) }

// secondAdjacentPortAddress reserves TCP control port + 2 for HTTP/1.1 CONNECT.
func secondAdjacentPortAddress(addr string) (string, error) { return offsetPortAddress(addr, 2) }

func nextPortLabel(addr string) string {
	out, err := adjacentPortAddress(addr)
	if err != nil {
		return "unavailable (choose control port below 65535)"
	}
	return portOf(out)
}

func secondNextPortLabel(addr string) string {
	out, err := secondAdjacentPortAddress(addr)
	if err != nil {
		return "unavailable (choose control port below 65534)"
	}
	return portOf(out)
}

func transportModeAllowsHTTP2(mode string) bool {
	return mode == transportAdaptive || mode == transportHTTP2 || mode == transportHTTPConnectAuto
}

func transportModeAllowsHTTP1(mode string) bool {
	return mode == transportAdaptive || mode == transportHTTP1 || mode == transportHTTPConnectAuto
}

// tunnelStreamConn adapts a bidirectional HTTP/2 CONNECT stream to net.Conn.
// Read and Write use separate HTTP/2 directions; each has one caller in the
// existing tunnel wire implementation. Deadlines are managed by heartbeats,
// HTTP timeouts and stream cancellation rather than socket deadlines.
type tunnelStreamConn struct {
	reader     io.ReadCloser
	writeFn    func([]byte) (int, error)
	closeFn    func() error
	localAddr  net.Addr
	remoteAddr net.Addr
	done       chan struct{}
	closeOnce  sync.Once
	deadlineMu sync.Mutex
	readTimer  *time.Timer
	writeTimer *time.Timer
}

type tunnelStreamAddr string

func (a tunnelStreamAddr) Network() string { return "tcp" }
func (a tunnelStreamAddr) String() string  { return string(a) }

func newTunnelStreamConn(reader io.ReadCloser, writeFn func([]byte) (int, error), closeFn func() error, local, remote string) *tunnelStreamConn {
	return &tunnelStreamConn{reader: reader, writeFn: writeFn, closeFn: closeFn, localAddr: tunnelStreamAddr(local), remoteAddr: tunnelStreamAddr(remote), done: make(chan struct{})}
}
func (c *tunnelStreamConn) Read(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	return c.reader.Read(p)
}
func (c *tunnelStreamConn) Write(p []byte) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}
	return c.writeFn(p)
}
func (c *tunnelStreamConn) Close() error {
	var out error
	c.closeOnce.Do(func() {
		close(c.done)
		c.deadlineMu.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
		}
		c.deadlineMu.Unlock()
		if c.reader != nil {
			out = c.reader.Close()
		}
		if c.closeFn != nil {
			if err := c.closeFn(); out == nil {
				out = err
			}
		}
	})
	return out
}
func (c *tunnelStreamConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *tunnelStreamConn) RemoteAddr() net.Addr { return c.remoteAddr }
func (c *tunnelStreamConn) setDeadlineTimer(target **time.Timer, deadline time.Time) {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if *target != nil {
		(*target).Stop()
		*target = nil
	}
	if deadline.IsZero() {
		return
	}
	delay := time.Until(deadline)
	if delay <= 0 {
		go c.Close()
		return
	}
	*target = time.AfterFunc(delay, func() { _ = c.Close() })
}
func (c *tunnelStreamConn) SetDeadline(t time.Time) error {
	c.setDeadlineTimer(&c.readTimer, t)
	c.setDeadlineTimer(&c.writeTimer, t)
	return nil
}
func (c *tunnelStreamConn) SetReadDeadline(t time.Time) error {
	c.setDeadlineTimer(&c.readTimer, t)
	return nil
}
func (c *tunnelStreamConn) SetWriteDeadline(t time.Time) error {
	c.setDeadlineTimer(&c.writeTimer, t)
	return nil
}

func constantTimeTokenMatch(got, want string) bool {
	return len(got) == len(want) && len(want) > 0 && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (h *hubServer) serveHTTP2Connect(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 2 {
		http.Error(w, "HTTP/2 required", http.StatusHTTPVersionNotSupported)
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "HTTP/2 CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	h.serveHTTPStream(w, r, transportHTTP2)
}

// serveHTTP1Connect accepts the standard HTTP/1.1 CONNECT method over TLS.
// After authenticating the HTTP header token, the handler hijacks the connection
// and carries the same inner authenticated S1T wire protocol as native TLS.
func (h *hubServer) serveHTTP1Connect(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		http.Error(w, "HTTP/1.1 required", http.StatusHTTPVersionNotSupported)
		return
	}
	if r.Method != http.MethodConnect {
		http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}
	if !transportAllowed(h.cfg.Transport, transportHTTP1) {
		http.Error(w, "HTTP/1.1 CONNECT not enabled by Hub policy", http.StatusUpgradeRequired)
		return
	}
	if !constantTimeTokenMatch(r.Header.Get(http2TokenHeader), h.cfg.Token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		logAuthFailure("rejected HTTP/1.1 CONNECT token authentication")
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection hijacking unavailable", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\nX-S1T-Transport: " + transportHTTP1 + "\r\n\r\n"); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	stream := &bufferedConn{Conn: conn, r: rw.Reader}
	_ = stream.SetDeadline(time.Time{})
	h.serveAuthorizedAgent(stream, transportHTTP1)
}

// serveHTTPStream carries the tunnel's authenticated wire protocol inside a
// full-duplex HTTP/2 CONNECT request body and response body.
func (h *hubServer) serveHTTPStream(w http.ResponseWriter, r *http.Request, observed string) {
	if !transportAllowed(h.cfg.Transport, observed) {
		http.Error(w, "HTTP stream transport is not allowed by Hub policy", http.StatusUpgradeRequired)
		return
	}
	if !constantTimeTokenMatch(r.Header.Get(http2TokenHeader), h.cfg.Token) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		logAuthFailure("rejected HTTP stream token authentication")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming response unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-S1T-Transport", observed)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	var writeMu sync.Mutex
	writeFn := func(p []byte) (int, error) {
		select {
		case <-r.Context().Done():
			return 0, net.ErrClosed
		default:
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		n, err := w.Write(p)
		if err == nil {
			flusher.Flush()
		}
		return n, err
	}
	closeFn := func() error {
		if r.Body != nil {
			return r.Body.Close()
		}
		return nil
	}
	c := newTunnelStreamConn(r.Body, writeFn, closeFn, r.Host, r.RemoteAddr)
	h.serveAuthorizedAgent(c, observed)
}

func connectAndRunAgentHTTP2(cfg Config, channel int) error {
	conn, err := dialHTTP2Connect(cfg)
	if err != nil {
		return err
	}
	return runAgentOverStream(conn, cfg, channel, transportHTTP2)
}

func connectAndRunAgentHTTP1(cfg Config, channel int) error {
	conn, err := dialHTTP1Connect(cfg)
	if err != nil {
		return err
	}
	return runAgentOverStream(conn, cfg, channel, transportHTTP1)
}

func connectAndRunAgentHTTPConnectAuto(cfg Config, channel int) error {
	conn, errH2 := dialHTTP2Connect(cfg)
	if errH2 == nil {
		return runAgentOverStream(conn, cfg, channel, transportHTTP2)
	}
	log.Printf("tunnel lane %d: HTTP/2 CONNECT failed; trying HTTP/1.1 CONNECT: %v", channel, errH2)
	conn, errH1 := dialHTTP1Connect(cfg)
	if errH1 != nil {
		return fmt.Errorf("HTTP/2 CONNECT failed (%v); HTTP/1.1 CONNECT fallback failed: %w", errH2, errH1)
	}
	return runAgentOverStream(conn, cfg, channel, transportHTTP1)
}

func runAgentOverStream(conn net.Conn, cfg Config, channel int, displayTransport string) error {
	adjustAgentChannels(1)
	defer adjustAgentChannels(-1)
	defer conn.Close()
	if cfg.Transport == transportAdaptive {
		agentPreferredTransport.Store(channel, displayTransport)
	}
	log.Printf("tunnel lane %d/%d connected via %s; forwarding through %d configured port mapping(s)", channel, cfg.TunnelChannels, displayTransport, len(normalizeConfig(cfg).Ports))
	targets := make(map[string]string, len(cfg.Ports))
	for _, p := range normalizeConfig(cfg).Ports {
		targets[p.ID] = p.Target
	}
	s := newAgentSession(conn, targets)
	s.run()
	return fmt.Errorf("Hub %s stream closed", displayTransport)
}

func dialHTTP2Connect(cfg Config) (net.Conn, error) {
	h2Addr, err := adjacentPortAddress(cfg.HubAddr)
	if err != nil {
		return nil, fmt.Errorf("derive HTTP/2 CONNECT endpoint from HubAddr: %w", err)
	}
	pin, err := normalizeFingerprint(cfg.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("invalid Hub certificate fingerprint: %w", err)
	}
	sni := strings.TrimSpace(cfg.TLSServerName)
	if sni == "" {
		if host, _, splitErr := net.SplitHostPort(cfg.HubAddr); splitErr == nil && net.ParseIP(host) == nil {
			sni = host
		}
	}
	tlsCfg := agentTLSConfig(pin, sni)
	tlsCfg.NextProtos = []string{"h2"}
	ctx, cancel := context.WithCancel(context.Background())
	pipeReader, pipeWriter := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+h2Addr, pipeReader)
	if err != nil {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, err
	}
	req.Host = h2Addr
	req.Header.Set(http2TokenHeader, cfg.Token)
	req.Header.Set("User-Agent", "ShahTunnel/"+version)
	req.ContentLength = -1
	tr := &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 12 * time.Second, IdleConnTimeout: 60 * time.Second, MaxIdleConnsPerHost: 1, DisableCompression: true}
	resp, err := tr.RoundTrip(req)
	if err == nil && resp == nil {
		err = errors.New("HTTP/2 transport returned an empty response without an error")
	}
	if err != nil {
		cancel()
		_ = pipeReader.CloseWithError(err)
		_ = pipeWriter.CloseWithError(err)
		tr.CloseIdleConnections()
		return nil, fmt.Errorf("HTTP/2 CONNECT stream to adjacent port failed: %w", err)
	}
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		tr.CloseIdleConnections()
		return nil, fmt.Errorf("HTTP/2 CONNECT rejected: protocol=%s status=%d body=%q", resp.Proto, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return newTunnelStreamConn(resp.Body, pipeWriter.Write, func() error {
		cancel()
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		tr.CloseIdleConnections()
		return nil
	}, "http2-client", h2Addr), nil
}

func dialHTTP1Connect(cfg Config) (net.Conn, error) {
	h1Addr, err := secondAdjacentPortAddress(cfg.HubAddr)
	if err != nil {
		return nil, fmt.Errorf("derive HTTP/1.1 CONNECT endpoint from HubAddr: %w", err)
	}
	pin, err := normalizeFingerprint(cfg.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("invalid Hub certificate fingerprint: %w", err)
	}
	sni := strings.TrimSpace(cfg.TLSServerName)
	if sni == "" {
		if host, _, splitErr := net.SplitHostPort(cfg.HubAddr); splitErr == nil && net.ParseIP(host) == nil {
			sni = host
		}
	}
	tlsCfg := agentTLSConfig(pin, sni)
	tlsCfg.NextProtos = []string{"http/1.1"}
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := tls.DialWithDialer(&d, "tcp", h1Addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("connect HTTP/1.1 CONNECT endpoint %s: %w", h1Addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
	// CONNECT uses the standard authority-form request target; after a 200
	// response the TLS socket becomes a byte stream carrying S1T framing.
	request := "CONNECT " + h1Addr + " HTTP/1.1\r\nHost: " + h1Addr + "\r\n" + http2TokenHeader + ": " + cfg.Token + "\r\nUser-Agent: ShahTunnel/" + version + "\r\nProxy-Connection: keep-alive\r\n\r\n"
	if err = writeFull(conn, []byte(request)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write HTTP/1.1 CONNECT request: %w", err)
	}
	reader := bufio.NewReaderSize(conn, maxWebSocketHeaders)
	req := &http.Request{Method: http.MethodConnect}
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read HTTP/1.1 CONNECT response: %w", err)
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 || resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("HTTP/1.1 CONNECT rejected: protocol=%s status=%d body=%q", resp.Proto, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: reader}, nil
}

func (h *hubServer) serveAgent(raw net.Conn, tlsCfg *tls.Config) {
	tc := tls.Server(raw, tlsCfg)
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		logAuthFailure("agent TLS handshake failed (details suppressed)")
		return
	}
	r := bufio.NewReaderSize(tc, maxWebSocketHeaders)
	prefix, err := r.Peek(4)
	if err != nil {
		logAuthFailure("incomplete reverse agent preface")
		return
	}
	observed := transportTCP
	var c net.Conn
	var authReader *bufio.Reader
	if bytes.Equal(prefix, []byte("GET ")) {
		observed = transportWebSocket
		if !transportAllowed(h.cfg.Transport, observed) {
			_ = writeFull(tc, []byte("HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
			logAuthFailure("WebSocket transport not enabled by Hub policy")
			return
		}
		if err := acceptWebSocketUpgrade(tc, r); err != nil {
			logAuthFailure("invalid WebSocket upgrade request")
			return
		}
		c = &websocketConn{Conn: tc, r: r, clientSide: false}
		authReader = bufio.NewReaderSize(c, 256)
	} else {
		if !transportAllowed(h.cfg.Transport, observed) {
			_ = writeFull(tc, []byte("NO\n"))
			logAuthFailure("TCP/TLS transport not enabled by Hub policy")
			return
		}
		c = &bufferedConn{Conn: tc, r: r}
		authReader = r
	}
	lineBytes, err := authReader.ReadSlice('\n')
	// A token handshake is under 300 bytes. Reject oversized lines instead
	// of allowing an unauthenticated peer to force unbounded allocation.
	if errors.Is(err, bufio.ErrBufferFull) {
		logAuthFailure("rejected oversized reverse agent handshake")
		return
	}
	protocol := authProtocol(string(lineBytes), h.cfg.Token)
	if err != nil || protocol == "" {
		_ = writeFull(c, []byte("NO\n"))
		logAuthFailure("rejected reverse agent authentication")
		return
	}
	if err = writeFull(c, []byte("OK\n")); err != nil {
		return
	}
	h.serveAuthorizedAgent(c, observed)
}

func (h *hubServer) serveAuthorizedAgent(c net.Conn, observed string) {
	defer c.Close()
	_ = c.SetDeadline(time.Time{})
	s := newHubSession(c)
	h.registerSession(s)
	log.Printf("outside agent lane connected via %s; active lanes=%d", observed, h.sessionCount())
	s.run()
	h.unregisterSession(s)
	log.Printf("outside agent lane disconnected via %s; active lanes=%d", observed, h.sessionCount())
}

// hubTLSConfig requires TLS 1.3 for the private Hub↔Agent control channel.
// The public forwarding ports are generic TCP and are not implicitly TLS-wrapped.
func hubTLSConfig(cert tls.Certificate) *tls.Config {
	// Preserve the legacy no-ALPN TLS profile for raw TCP/TLS. A client explicitly
	// selecting WebSocket/TLS offers HTTP/1.1 and gets the matching ALPN profile.
	webSocketConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, proto := range hello.SupportedProtos {
			if proto == "http/1.1" {
				return webSocketConfig, nil
			}
		}
		return nil, nil
	}
	return base
}

// agentTLSConfig uses a pinned self-signed Hub certificate. InsecureSkipVerify
// disables CA/name validation only; VerifyConnection below still rejects every
// certificate whose full DER SHA-256 fingerprint does not exactly match the pin.
func agentTLSConfig(pin []byte, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: true, // verification is performed by the constant-time fingerprint pin below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("hub presented no certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if len(pin) != sha256.Size || subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("hub TLS certificate fingerprint mismatch")
			}
			return nil
		},
	}
}

// isRetryableAcceptError classifies transient accept failures. Backing off here
// avoids a tight CPU/log loop when a listener temporarily runs out of resources.
func isRetryableAcceptError(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	for _, target := range []error{syscall.EINTR, syscall.ECONNABORTED, syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM} {
		if errors.Is(err, target) {
			return true
		}
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Temporary()
}

func acceptRetryDelay(attempt int) time.Duration {
	delay := 25 * time.Millisecond
	for i := 0; i < attempt && delay < time.Second; i++ {
		delay *= 2
	}
	if delay > time.Second {
		delay = time.Second
	}
	return delay
}

func runHub(cfg Config) error {
	cfg = normalizeConfig(cfg)
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load hub certificate/key: %w; run setup again", err)
	}
	control, err := net.Listen("tcp", cfg.ControlListen)
	if err != nil {
		return fmt.Errorf("listen control %s: %w", cfg.ControlListen, err)
	}
	defer control.Close()
	type listenerMap struct {
		listener net.Listener
		id       string
	}
	listeners := make([]listenerMap, 0, len(cfg.Ports))
	for _, p := range cfg.Ports {
		ln, e := net.Listen("tcp", p.Listen)
		if e != nil {
			for _, opened := range listeners {
				_ = opened.listener.Close()
			}
			return fmt.Errorf("listen public mapping %q (%s): %w", p.ID, p.Listen, e)
		}
		listeners = append(listeners, listenerMap{listener: ln, id: p.ID})
	}
	defer func() {
		for _, p := range listeners {
			_ = p.listener.Close()
		}
	}()
	h := &hubServer{
		cfg:           cfg,
		sessions:      make(map[*hubSession]struct{}),
		pendingPublic: make(chan struct{}, maxPendingPublicConnections),
	}
	var h2Server *http.Server
	if transportModeAllowsHTTP2(cfg.Transport) {
		h2Addr, addrErr := adjacentPortAddress(cfg.ControlListen)
		if addrErr != nil {
			return fmt.Errorf("derive HTTP/2 CONNECT listener address: %w", addrErr)
		}
		h2Listener, listenErr := net.Listen("tcp", h2Addr)
		if listenErr != nil {
			return fmt.Errorf("listen HTTP/2 CONNECT on %s: %w (allow TCP on the control port plus one)", h2Addr, listenErr)
		}
		h2Server = &http.Server{
			Handler:           http.HandlerFunc(h.serveHTTP2Connect),
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}},
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 * 1024,
		}
		go func() {
			if serveErr := h2Server.ServeTLS(h2Listener, "", ""); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				log.Printf("HTTP/2 CONNECT listener stopped: %v", serveErr)
			}
		}()
		defer h2Server.Close()
		log.Printf("HTTP/2 CONNECT listener enabled on TCP %s", h2Addr)
	}
	var h1Server *http.Server
	if transportModeAllowsHTTP1(cfg.Transport) {
		h1Addr, addrErr := secondAdjacentPortAddress(cfg.ControlListen)
		if addrErr != nil {
			return fmt.Errorf("derive HTTP/1.1 CONNECT listener address: %w", addrErr)
		}
		h1Listener, listenErr := net.Listen("tcp", h1Addr)
		if listenErr != nil {
			if h2Server != nil {
				_ = h2Server.Close()
			}
			return fmt.Errorf("listen HTTP/1.1 CONNECT on %s: %w (allow TCP on the control port plus two)", h1Addr, listenErr)
		}
		h1Server = &http.Server{
			Handler:           http.HandlerFunc(h.serveHTTP1Connect),
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}},
			ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024,
		}
		go func() {
			if serveErr := h1Server.ServeTLS(h1Listener, "", ""); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				log.Printf("HTTP/1.1 CONNECT listener stopped: %v", serveErr)
			}
		}()
		defer h1Server.Close()
		log.Printf("HTTP/1.1 CONNECT listener enabled on TCP %s", h1Addr)
	}
	startMetricsReporter("hub")
	for _, p := range listeners {
		go h.acceptPublic(p.listener, p.id)
	}
	tlsCfg := hubTLSConfig(cert)
	log.Printf("HUB listening for agent on configured control port; public mappings=%d", len(listeners))
	// Bound concurrent unauthenticated control connections so a burst of
	// slow handshakes cannot create an unbounded number of goroutines.
	controlSlots := make(chan struct{}, 16)
	acceptErrors := 0
	for {
		c, err := control.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("control listener closed: %w", err)
			}
			if isRetryableAcceptError(err) {
				acceptErrors++
				if acceptErrors == 1 {
					log.Printf("temporary control accept error; backing off: %v", err)
				}
				time.Sleep(acceptRetryDelay(acceptErrors - 1))
				continue
			}
			return fmt.Errorf("accept control: %w", err)
		}
		acceptErrors = 0
		select {
		case controlSlots <- struct{}{}:
			go func(conn net.Conn) {
				defer func() { <-controlSlots }()
				h.serveAgent(conn, tlsCfg)
			}(c)
		default:
			_ = c.Close()
		}
	}
}

func runRelay(cfg Config) error {
	cfg = normalizeConfig(cfg)
	type relayListener struct {
		ln         net.Listener
		target, id string
	}
	listeners := make([]relayListener, 0, len(cfg.Ports))
	for _, p := range cfg.Ports {
		ln, err := net.Listen("tcp", p.Listen)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.ln.Close()
			}
			return fmt.Errorf("listen Relay mapping %q: %w", p.ID, err)
		}
		listeners = append(listeners, relayListener{ln: ln, target: p.Target, id: p.ID})
	}
	defer func() {
		for _, p := range listeners {
			_ = p.ln.Close()
		}
	}()
	startMetricsReporter("relay")
	metricConnected.Store(true)
	limit := make(chan struct{}, maxStreams)
	for _, p := range listeners {
		p := p
		go func() {
			acceptErrors := 0
			for {
				c, err := p.ln.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						log.Printf("Relay listener stopped for mapping %q", p.id)
						return
					}
					if isRetryableAcceptError(err) {
						acceptErrors++
						if acceptErrors == 1 {
							log.Printf("temporary Relay accept error for mapping %q; backing off", p.id)
						}
						time.Sleep(acceptRetryDelay(acceptErrors - 1))
						continue
					}
					log.Printf("Relay listener stopped for mapping %q after accept error: %v", p.id, err)
					return
				}
				acceptErrors = 0
				select {
				case limit <- struct{}{}:
					metricActive.Add(1)
					metricTotal.Add(1)
					go func(client net.Conn) { defer func() { <-limit; metricActive.Add(-1) }(); relayTCP(client, p.target) }(c)
				default:
					_ = c.Close()
				}
			}
		}()
	}
	log.Printf("RELAY ready with %d mapping(s); endpoint addresses suppressed", len(listeners))
	select {}
}

func relayTCP(client net.Conn, target string) {
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	upstream, err := d.Dial("tcp", target)
	if err != nil {
		log.Printf("Relay upstream unavailable (details suppressed)")
		_ = client.Close()
		return
	}
	tuneTCPConn(client)
	tuneTCPConn(upstream)
	defer client.Close()
	defer upstream.Close()
	finished := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(counterWriter{w: upstream, counter: &metricSent}, client)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		finished <- struct{}{}
	}()
	_, _ = io.Copy(counterWriter{w: client, counter: &metricReceived}, upstream)
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
	}
}

func authProtocol(line, token string) string {
	// Accept only the exact protocol line. Trimming arbitrary whitespace could
	// make malformed or concatenated pre-authentication data look valid.
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	const prefix = "RREV3 "
	if !strings.HasPrefix(line, prefix) {
		return ""
	}
	got := strings.TrimPrefix(line, prefix)
	if len(got) == len(token) && subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 {
		return "RREV3"
	}
	return ""
}
func validAuth(line, token string) bool { return authProtocol(line, token) != "" }

func runAgent(cfg Config) error {
	cfg = normalizeConfig(cfg)
	pin, err := normalizeFingerprint(cfg.Fingerprint)
	if err != nil {
		return err
	}
	if cfg.TunnelChannels < 1 || cfg.TunnelChannels > maxTunnelChannels {
		return fmt.Errorf("tunnel_channels must be between 1 and %d", maxTunnelChannels)
	}
	startMetricsReporter("agent")
	log.Printf("starting %d independent authenticated tunnel lanes", cfg.TunnelChannels)
	var workers sync.WaitGroup
	for i := 1; i <= cfg.TunnelChannels; i++ {
		workers.Add(1)
		go func(channel int) {
			defer workers.Done()
			runAgentWorker(cfg, pin, channel)
		}(i)
	}
	workers.Wait()
	return nil
}

func runAgentWorker(cfg Config, pin []byte, channel int) {
	backoff := time.Second
	for {
		attemptStarted := time.Now()
		if err := connectAndRunAgent(cfg, pin, channel); err != nil {
			msg := err.Error()
			msg = strings.ReplaceAll(msg, cfg.HubAddr, "[hub-address-redacted]")
			for _, p := range normalizeConfig(cfg).Ports {
				msg = strings.ReplaceAll(msg, p.Target, "[target-redacted]")
			}
			log.Printf("tunnel lane %d/%d ended: %s", channel, cfg.TunnelChannels, msg)
		}
		// Each lane reconnects independently. One unstable TCP path must not
		// restart or tear down the other healthy lanes.
		if time.Since(attemptStarted) >= time.Minute {
			backoff = time.Second
		}
		delay := jitteredBackoff(backoff)
		log.Printf("retrying tunnel lane %d/%d in %s (with jitter)", channel, cfg.TunnelChannels, delay)
		time.Sleep(delay)
		backoff *= 2
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// jitteredBackoff avoids synchronized reconnect spikes after a shared outage.
// The delay stays within +/-20% of the base interval.
func jitteredBackoff(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	span := int64(base / 5)
	if span <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(2*span+1))
	if err != nil {
		return base
	}
	return base - time.Duration(span) + time.Duration(n.Int64())
}

func isAdaptiveTransport(mode string) bool {
	switch mode {
	case transportTCP, transportWebSocket, transportHTTP2, transportHTTP1:
		return true
	default:
		return false
	}
}

func adaptiveTransportCandidates(preferred string) []string {
	// Order the implemented transports with the last successful path first.
	all := []string{transportTCP, transportWebSocket, transportHTTP2, transportHTTP1}
	out := make([]string, 0, len(all))
	if isAdaptiveTransport(preferred) {
		out = append(out, preferred)
	}
	for _, mode := range all {
		if mode != preferred {
			out = append(out, mode)
		}
	}
	return out
}

func connectAndRunAgent(cfg Config, pin []byte, channel int) error {
	mode := cfg.Transport
	if mode == "" {
		mode = transportAuto
	}
	if mode != transportAuto && mode != transportAdaptive {
		return connectAndRunAgentWithTransport(cfg, pin, channel, mode)
	}

	preferred := transportTCP
	if mode == transportAdaptive {
		if v, ok := agentPreferredTransport.Load(channel); ok {
			if saved, ok := v.(string); ok && isAdaptiveTransport(saved) {
				preferred = saved
			}
		}
	}
	candidates := []string{transportTCP, transportWebSocket}
	if mode == transportAdaptive {
		candidates = adaptiveTransportCandidates(preferred)
	}

	// Every candidate is a real transport implementation in this build. A failed
	// connect, handshake, or ended lane moves to the next candidate immediately.
	// The outer worker's jittered backoff still applies after every candidate fails.
	var lastErr error
	for i, candidate := range candidates {
		err := connectAndRunAgentWithTransport(cfg, pin, channel, candidate)
		if err == nil {
			return nil
		}
		lastErr = err
		if i < len(candidates)-1 {
			if mode == transportAdaptive {
				log.Printf("tunnel lane %d: adaptive transport %s failed or closed; trying %s", channel, candidate, candidates[i+1])
			} else {
				log.Printf("tunnel lane %d: TCP/TLS attempt failed or closed; trying WebSocket/TLS fallback", channel)
			}
		}
	}
	if lastErr == nil {
		lastErr = net.ErrClosed
	}
	return lastErr
}

func connectAndRunAgentWithTransport(cfg Config, pin []byte, channel int, mode string) error {
	switch mode {
	case transportHTTP2:
		return connectAndRunAgentHTTP2(cfg, channel)
	case transportHTTP1:
		return connectAndRunAgentHTTP1(cfg, channel)
	case transportHTTPConnectAuto:
		return connectAndRunAgentHTTPConnectAuto(cfg, channel)
	}
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	sni := strings.TrimSpace(cfg.TLSServerName)
	if sni == "" {
		if host, _, splitErr := net.SplitHostPort(cfg.HubAddr); splitErr == nil && net.ParseIP(host) == nil {
			sni = host
		}
	}
	tlsCfg := agentTLSConfig(pin, sni)
	if mode == transportWebSocket {
		tlsCfg.NextProtos = []string{"http/1.1"}
	}
	tlsConn, err := tls.DialWithDialer(&d, "tcp", cfg.HubAddr, tlsCfg)
	if err != nil {
		return err
	}
	var c net.Conn = tlsConn
	if mode == transportWebSocket {
		wsHost := strings.TrimSpace(sni)
		if wsHost == "" {
			wsHost, _, _ = net.SplitHostPort(cfg.HubAddr)
		}
		if _, port, splitErr := net.SplitHostPort(cfg.HubAddr); splitErr == nil {
			wsHost = net.JoinHostPort(wsHost, port)
		}
		c, err = clientWebSocketUpgrade(tlsConn, wsHost)
		if err != nil {
			_ = tlsConn.Close()
			return err
		}
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err = writeFull(c, []byte("RREV3 "+cfg.Token+"\n")); err != nil {
		return err
	}
	reply, err := bufio.NewReaderSize(c, 64).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read Hub authentication response: %w", err)
	}
	if reply != "OK\n" {
		return errors.New("hub rejected token or selected transport")
	}
	_ = c.SetDeadline(time.Time{})
	adjustAgentChannels(1)
	defer adjustAgentChannels(-1)
	if cfg.Transport == transportAdaptive {
		agentPreferredTransport.Store(channel, mode)
	}
	log.Printf("tunnel lane %d/%d connected via %s; forwarding through %d configured port mapping(s)", channel, cfg.TunnelChannels, mode, len(normalizeConfig(cfg).Ports))
	targets := make(map[string]string, len(cfg.Ports))
	for _, p := range normalizeConfig(cfg).Ports {
		targets[p.ID] = p.Target
	}
	s := newAgentSession(c, targets)
	s.run()
	return errors.New("hub connection closed")
}

func normalizeConfig(c Config) Config {
	if c.Role == "hub" || c.Role == "agent" {
		c.Transport = strings.ToLower(strings.TrimSpace(c.Transport))
		if c.Transport == "" {
			c.Transport = transportAuto
		}
	}
	// Upgrade existing Agent profiles to the current independent-lane performance profile.
	// Each lane reconnects independently; no Hub-side config change is required.
	if c.Role == "agent" && c.TunnelChannels < defaultTunnelChannels {
		c.TunnelChannels = defaultTunnelChannels
	}
	if len(c.Ports) == 0 {
		if c.Role == "hub" && c.PublicListen != "" {
			c.Ports = []PortMapping{{ID: "main", Listen: c.PublicListen}}
		}
		if c.Role == "agent" && c.Target != "" {
			c.Ports = []PortMapping{{ID: "main", Target: c.Target}}
		}
	}
	if len(c.Ports) > 0 {
		if c.Role == "hub" {
			c.PublicListen = c.Ports[0].Listen
		} else if c.Role == "agent" {
			c.Target = c.Ports[0].Target
		}
	}
	return c
}

// validTLSServerName accepts a DNS hostname for TLS SNI. It intentionally does
// not accept URL syntax, IP literals, whitespace, or wildcard names.
func validTLSServerName(name string) bool {
	if name == "" || len(name) > 253 || strings.TrimSpace(name) != name || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func validateConfig(c Config) error {
	c = normalizeConfig(c)
	if c.Version == "" {
		return errors.New("missing config version")
	}
	if c.Role != "hub" && c.Role != "agent" && c.Role != "relay" {
		return errors.New("role must be hub, agent, or relay")
	}
	if (c.Role == "hub" || c.Role == "agent") && !validTransportMode(c.Transport) {
		return fmt.Errorf("unsupported transport %q (supported: auto, adaptive, tcp_tls, websocket_tls, http2_connect, http1_connect, http_connect_auto)", c.Transport)
	}
	if c.Role == "agent" && (c.TunnelChannels < 1 || c.TunnelChannels > maxTunnelChannels) {
		return fmt.Errorf("tunnel_channels must be between 1 and %d", maxTunnelChannels)
	}
	if len(c.Token) < 48 || len(c.Token) > 240 || strings.ContainsAny(c.Token, "\r\n") {
		return errors.New("token must be 48–240 characters and contain no line breaks")
	}
	if c.DNSFilterEnabled {
		// The filter can run on HUB, AGENT, or RELAY. In HUB mode it is a
		// separate DNS listener: clients must explicitly point DNS at the Hub
		// address and their observed source IP must match the allowlist. This
		// TCP reverse tunnel is not itself a full-device VPN/IP router.
		if err := validateTCPAddress("DNS filter listen address", c.DNSFilterListen); err != nil {
			return err
		}
		if err := validateTCPAddress("DNS upstream", c.DNSFilterUpstream); err != nil {
			return err
		}
		if len(c.DNSFilterAllowedCIDRs) == 0 {
			return errors.New("DNS filter requires at least one allowed source IP/CIDR; avoid creating an unrestricted public DNS resolver")
		}
		for _, cidr := range c.DNSFilterAllowedCIDRs {
			_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				return fmt.Errorf("invalid DNS filter allowed CIDR %q", cidr)
			}
			ones, bits := network.Mask.Size()
			if ones == 0 && bits > 0 {
				return fmt.Errorf("DNS filter CIDR %q is unrestricted; use specific client IPs/subnets, not /0", cidr)
			}
		}
		// The DNS filter binds both UDP and TCP on this port. Prevent collisions
		// with this process's TCP listeners before saving the configuration.
		_, dnsPortText, _ := net.SplitHostPort(c.DNSFilterListen)
		dnsPort, _ := strconv.Atoi(dnsPortText)
		if c.Role == "hub" {
			check := []string{c.ControlListen}
			if transportModeAllowsHTTP2(c.Transport) {
				if a, err := adjacentPortAddress(c.ControlListen); err == nil {
					check = append(check, a)
				}
			}
			if transportModeAllowsHTTP1(c.Transport) {
				if a, err := secondAdjacentPortAddress(c.ControlListen); err == nil {
					check = append(check, a)
				}
			}
			for _, m := range c.Ports {
				check = append(check, m.Listen)
			}
			for _, addr := range check {
				if _, portText, err := net.SplitHostPort(addr); err == nil {
					port, _ := strconv.Atoi(portText)
					if port == dnsPort {
						return fmt.Errorf("DNS filter port %d conflicts with another HUB listener; choose another DNS port", dnsPort)
					}
				}
			}
		}
	}
	if len(c.Ports) == 0 {
		return errors.New("at least one port mapping is required")
	}
	ids, addrs := map[string]bool{}, map[string]bool{}
	if c.Role == "hub" {
		if err := validateTCPAddress("control listener", c.ControlListen); err != nil {
			return err
		}
		if c.CertFile == "" || c.KeyFile == "" {
			return errors.New("cert_file/key_file required for hub")
		}
		if transportModeAllowsHTTP2(c.Transport) {
			if _, err := adjacentPortAddress(c.ControlListen); err != nil {
				return fmt.Errorf("HTTP/2 CONNECT port: %w", err)
			}
		}
		if transportModeAllowsHTTP1(c.Transport) {
			if _, err := secondAdjacentPortAddress(c.ControlListen); err != nil {
				return fmt.Errorf("HTTP/1.1 CONNECT port: %w", err)
			}
		}
		_, controlPortText, _ := net.SplitHostPort(c.ControlListen)
		controlPort, _ := strconv.Atoi(controlPortText)
		reservedPorts := map[int]bool{controlPort: true}
		if transportModeAllowsHTTP2(c.Transport) {
			h2Addr, _ := adjacentPortAddress(c.ControlListen)
			_, pText, _ := net.SplitHostPort(h2Addr)
			p, _ := strconv.Atoi(pText)
			reservedPorts[p] = true
		}
		if transportModeAllowsHTTP1(c.Transport) {
			h1Addr, _ := secondAdjacentPortAddress(c.ControlListen)
			_, pText, _ := net.SplitHostPort(h1Addr)
			p, _ := strconv.Atoi(pText)
			reservedPorts[p] = true
		}
		for _, p := range c.Ports {
			if !validMappingID(p.ID) {
				return fmt.Errorf("invalid mapping id %q (use letters, numbers, - or _)", p.ID)
			}
			if ids[p.ID] {
				return fmt.Errorf("duplicate mapping id %q", p.ID)
			}
			ids[p.ID] = true
			if err := validateTCPAddress("listen for mapping "+p.ID, p.Listen); err != nil {
				return err
			}
			_, lpText, _ := net.SplitHostPort(p.Listen)
			lp, _ := strconv.Atoi(lpText)
			if reservedPorts[lp] {
				return fmt.Errorf("mapping %q uses reserved control/transport port %s", p.ID, lpText)
			}
			if addrs[p.Listen] {
				return fmt.Errorf("duplicate listen address %q", p.Listen)
			}
			addrs[p.Listen] = true
		}
	} else if c.Role == "agent" {
		if err := validateTCPAddress("hub address", c.HubAddr); err != nil {
			return err
		}
		if c.TLSServerName != "" && !validTLSServerName(c.TLSServerName) {
			return errors.New("tls_server_name must be a DNS hostname (no URL, port, IP, or whitespace)")
		}
		for _, p := range c.Ports {
			if !validMappingID(p.ID) {
				return fmt.Errorf("invalid mapping id %q (use letters, numbers, - or _)", p.ID)
			}
			if ids[p.ID] {
				return fmt.Errorf("duplicate mapping id %q", p.ID)
			}
			ids[p.ID] = true
			if err := validateTCPAddress("target for mapping "+p.ID, p.Target); err != nil {
				return err
			}
		}
		if _, err := normalizeFingerprint(c.Fingerprint); err != nil {
			return err
		}
	} else {
		for _, p := range c.Ports {
			if !validMappingID(p.ID) {
				return fmt.Errorf("invalid mapping id %q (use letters, numbers, - or _)", p.ID)
			}
			if ids[p.ID] {
				return fmt.Errorf("duplicate mapping id %q", p.ID)
			}
			ids[p.ID] = true
			if err := validateTCPAddress("Relay listen for mapping "+p.ID, p.Listen); err != nil {
				return err
			}
			if addrs[p.Listen] {
				return fmt.Errorf("duplicate relay listen address %q", p.Listen)
			}
			addrs[p.Listen] = true
			if err := validateTCPAddress("Iran Hub public target for mapping "+p.ID, p.Target); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateTCPAddress(label, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid %s address: %w", label, err)
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("%s host/address cannot be empty; use an explicit IP or hostname", label)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%s port must be a number from 1 to 65535", label)
	}
	return nil
}

func validMappingID(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func normalizeFingerprint(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "sha256:"))
	s = strings.ReplaceAll(s, ":", "")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, errors.New("fingerprint must be SHA-256 hex (64 hex chars, colons optional)")
	}
	return b, nil
}
func loadConfig() (Config, error) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w; run 'ravanreverse setup' first", configPath, err)
	}
	var c Config
	if err = json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	c = normalizeConfig(c)
	if err = validateConfig(c); err != nil {
		return Config{}, err
	}
	return c, nil
}
func saveConfig(c Config) error {
	c = normalizeConfig(c)
	if err := validateConfig(c); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(configPath), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(configPath), ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, configPath); err != nil {
		return err
	}
	return os.Chmod(configPath, 0600)
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var stdinReader = bufio.NewReader(os.Stdin)
var wizardStep int

const (
	ansiReset    = "\033[0m"
	ansiCyan     = "\033[36m"
	ansiBlue     = "\033[34m"
	ansiPurple   = "\033[35m"
	ansiGreen    = "\033[32m"
	ansiYellow   = "\033[33m"
	ansiRed      = "\033[31m"
	ansiPinkGlow = "\033[1;38;2;255;92;200m"
	ansiBold     = "\033[1m"
	ansiDim      = "\033[2m"
)

func paint(code, value string) string {
	if os.Getenv("NO_COLOR") != "" || strings.EqualFold(os.Getenv("TERM"), "dumb") {
		return value
	}
	return code + value + ansiReset
}

// shahTunnelLogoPixels is a compact 22×22 color-index rendition of the project
// logo, embedded in the main program so the menu does not depend on an external
// image file. Each terminal cell paints two vertical pixels using the upper-half
// block glyph; terminals without color receive a monochrome character rendition.
var shahTunnelLogoPalette = [...]uint32{
	0x26a9db,
	0x2663ba,
	0x254ca1,
	0x074494,
	0x22298c,
	0x092663,
	0x012868,
	0x011a42,
	0x0b0f50,
	0x020d25,
	0x020915,
	0x000414,
	0x02070f,
	0x01050e,
	0x000309,
	0x000003,
}

var shahTunnelLogoPixels = []string{
	"cccccccaaaaaaaaccccccc",
	"cccccadffeddefedaccccc",
	"dcccef9763333659eeaccc",
	"cccf933677ab775347eccc",
	"cee637deef55fedd744bcc",
	"ea36fb77700017c9af549d",
	"c37f77a3017a303977f84a",
	"37a7761152005733465f84",
	"5c671173000001484256b4",
	"e5671a1006752111825127",
	"967a32001f9be741537321",
	"56ac3101155139a9737681",
	"7ab765013210075fa3a731",
	"95356c611332137f937118",
	"315f67f94111112a743699",
	"1979969dfa51111187ab99",
	"2977f303aba971114f79d9",
	"223355001555b8124e7997",
	"b9977a31111449449a9e99",
	"ccd97ef944448548faccad",
	"ddca9dbfd78866afcdcbdd",
	"ddddcdddea637fedddddeb",
}

func logoPixelIndex(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c-'a') + 10
	}
	return 15
}

func logoLuminance(rgb uint32) int {
	r := int((rgb >> 16) & 0xff)
	g := int((rgb >> 8) & 0xff)
	b := int(rgb & 0xff)
	return (299*r + 587*g + 114*b) / 1000
}

// drawShahTunnelLogo is intentionally disabled to keep the terminal menu compact.
func drawShahTunnelLogo() {}

func uiRule() {
	fmt.Println(paint(ansiPinkGlow, "  ──────────────────────────────────────────────────────────────"))
}

// shahTunnelHeaderArt keeps the requested banner's spacing stable; do not
// reflow or truncate these lines as part of menu rendering.
var shahTunnelHeaderArt = []string{
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

const shahTunnelRouteWidth = 62

// shahTunnelRouteArt draws the live data path and makes it explicit that TLS
// protects the Hub↔Agent control tunnel, while the client/target-facing legs
// are ordinary TCP forwarding endpoints.
var shahTunnelRouteArt = func() []string {
	line := func(text string) string {
		return "  │" + centerUI(text, shahTunnelRouteWidth) + "│"
	}
	return []string{
		"  ╭" + strings.Repeat("─", shahTunnelRouteWidth) + "╮",
		line("NETWORK ROUTE  /  TCP FORWARDING"),
		line("CLIENT ── TCP ──▶ HUB ═ TLS 1.3 + TOKEN AUTH ═▶ AGENT"),
		line("PATHS: TCP/TLS | WS/TLS | H2 CONNECT | H1 CONNECT"),
		line("OPTION 7: ADAPTIVE FAILOVER ACROSS 4 PATHS"),
		line("CERT PINNING • TOKEN AUTH • TLS 1.3"),
		"  ╰" + strings.Repeat("─", shahTunnelRouteWidth) + "╯",
	}
}()

func uiRouteDiagram() {
	for i, line := range shahTunnelRouteArt {
		color := ansiDim
		switch i {
		case 1:
			color = ansiPurple + ansiBold
		case 2, 3:
			color = ansiCyan + ansiBold
		case 4, 5:
			color = ansiDim
		}
		fmt.Println(paintNeonRouteLine(i, line, color))
	}
}

// paintNeonHeaderLine renders box borders in the same bright pink as the
// Command Deck frame while keeping the text inside each box independently colored.
func paintNeonHeaderLine(index int, line, contentColor string) string {
	if index == 0 || index == 3 || index == 9 || index == 10 || index == 13 {
		return paint(ansiPinkGlow, line)
	}
	runes := []rune(line)
	left, right := -1, -1
	for i, r := range runes {
		if r == '|' || r == '║' {
			if left < 0 {
				left = i
			}
			right = i
		}
	}
	if left < 0 || right <= left {
		return paint(contentColor, line)
	}
	return string(runes[:left]) + paint(ansiPinkGlow, string(runes[left])) + paint(contentColor, string(runes[left+1:right])) + paint(ansiPinkGlow, string(runes[right])) + string(runes[right+1:])
}

// paintNeonRouteLine uses pink only for the drawing's frame and preserves the
// cyan/green text coloring inside it. ANSI terminals cannot create a true blur
// halo, so bright true-color magenta + bold is the portable neon approximation.
func paintNeonRouteLine(index int, line, contentColor string) string {
	if index == 0 || index == len(shahTunnelRouteArt)-1 {
		return paint(ansiPinkGlow, line)
	}
	runes := []rune(line)
	left, right := -1, -1
	for i, r := range runes {
		if r == '│' {
			if left < 0 {
				left = i
			}
			right = i
		}
	}
	if left < 0 || right <= left {
		return paint(contentColor, line)
	}
	return string(runes[:left]) + paint(ansiPinkGlow, string(runes[left])) + paint(contentColor, string(runes[left+1:right])) + paint(ansiPinkGlow, string(runes[right])) + string(runes[right+1:])
}

func uiHeader(_, _ string) {
	fmt.Println()
	drawShahTunnelLogo()
	fmt.Println()
	for i, line := range shahTunnelHeaderArt {
		if i == 10 {
			fmt.Println()
			uiRouteDiagram()
			fmt.Println()
		}
		// Report the actual service state in the brand banner instead of always
		// claiming that a private session is active.
		if i == 8 {
			if tunnelIsActive() {
				line = "        |     SESSION: ACTIVE / PRIVATE ROUTE      |"
			} else {
				line = "        |   SESSION: STANDBY / SETUP REQUIRED      |"
			}
		}
		color := ansiDim
		switch i {
		case 0, 3, 9:
			color = ansiCyan + ansiBold
		case 1, 4, 6, 11:
			color = ansiCyan + ansiBold
		case 10, 13:
			color = ansiPurple + ansiBold
		case 12:
			color = ansiGreen + ansiBold
		case 2, 5, 7, 8:
			color = ansiDim
		}
		fmt.Println(paintNeonHeaderLine(i, line, color))
	}
	fmt.Println()
}

func centerUI(s string, width int) string {
	if len([]rune(s)) >= width {
		return s
	}
	left := (width - len([]rune(s))) / 2
	right := width - len([]rune(s)) - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

func readAnswer(def string) string {
	v, err := stdinReader.ReadString('\n')
	if err != nil && len(v) == 0 {
		return def
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}

func ask(prompt, def string) string {
	fmt.Printf("%s", paint(ansiCyan+ansiBold, prompt))
	if def != "" {
		fmt.Printf(" %s", paint(ansiDim, "[default: "+def+"]"))
	}
	fmt.Printf(" %s ", paint(ansiCyan+ansiBold, "›"))
	return readAnswer(def)
}

func wizardAsk(prompt, def string) string {
	wizardStep++
	fmt.Printf("\n  %s %s\n", paint(ansiPurple+ansiBold, fmt.Sprintf("◆ STEP %02d", wizardStep)), paint(ansiBold, prompt))
	if def != "" {
		fmt.Printf("    %s\n", paint(ansiDim, "Suggested: "+def))
	}
	fmt.Printf("    %s ", paint(ansiCyan+ansiBold, "↳"))
	return readAnswer(def)
}

func wizardAskTransport(prompt string) (string, error) {
	fmt.Printf("\n  %s\n", paint(ansiCyan+ansiBold, "OUTER TUNNEL TRANSPORT"))
	fmt.Printf("  %s\n", paint(ansiGreen, "1) TCP/TLS — implemented"))
	fmt.Printf("  %s\n", paint(ansiGreen, "2) WebSocket/TLS — implemented"))
	fmt.Printf("  %s\n", paint(ansiGreen, "3) HTTP/2 CONNECT — implemented on control port + 1"))
	fmt.Printf("  %s\n", paint(ansiGreen, "4) HTTP/1.1 CONNECT/TLS — implemented on control port + 2"))
	fmt.Printf("  %s\n", paint(ansiGreen, "5) HTTP CONNECT fallback — HTTP/2, then HTTP/1.1"))
	fmt.Printf("  %s\n", "6) Automatic fallback — TCP/TLS, then WebSocket/TLS")
	fmt.Printf("  %s\n", paint(ansiPinkGlow, "7) FULL ADAPTIVE FAILOVER — all 4 implemented transports"))
	choice := wizardAsk(prompt+" (1-7)", "7")
	switch choice {
	case "1":
		return transportTCP, nil
	case "2":
		return transportWebSocket, nil
	case "3":
		return transportHTTP2, nil
	case "4":
		return transportHTTP1, nil
	case "5":
		return transportHTTPConnectAuto, nil
	case "6":
		return transportAuto, nil
	case "7":
		return transportAdaptive, nil
	default:
		return "", errors.New("invalid transport selection; enter a number from 1 to 7")
	}
}

func wizardYesNo(prompt, def string) bool {
	return strings.EqualFold(wizardAsk(prompt, def), "y")
}

func uiSuccess(message string) { fmt.Printf("  %s %s\n", paint(ansiGreen+ansiBold, "✓"), message) }
func uiInfo(message string)    { fmt.Printf("  %s %s\n", paint(ansiCyan, "◇"), message) }
func uiWarn(message string)    { fmt.Printf("  %s %s\n", paint(ansiYellow, "!"), message) }

type uiCardRow struct {
	Text  string
	Color string
}

// uiCard renders a compact, independently colored panel. Width is based on
// plain text so ANSI color codes never distort the alignment.
func uiCard(title string, rows []uiCardRow, _ string) {
	width := len([]rune(title))
	if width < 34 {
		width = 34
	}
	for _, row := range rows {
		if n := len([]rune(row.Text)); n > width {
			width = n
		}
	}
	if width > 76 {
		width = 76
	}
	border := func(s string) string { return paint(ansiPinkGlow, s) }
	fmt.Printf("  %s\n", border("╭"+strings.Repeat("─", width+2)+"╮"))
	titlePadding := width - len([]rune(title))
	fmt.Printf("  %s %s%s %s\n", border("│"), paint(ansiBold, title), strings.Repeat(" ", titlePadding), border("│"))
	for _, row := range rows {
		text := row.Text
		visible := len([]rune(text))
		if visible > width {
			// Long values are wrapped rather than silently truncated.
			for len([]rune(text)) > width {
				runes := []rune(text)
				part := string(runes[:width])
				fmt.Printf("  %s %s%s %s\n", border("│"), paint(row.Color, part), "", border("│"))
				text = string(runes[width:])
			}
			visible = len([]rune(text))
		}
		fmt.Printf("  %s %s%s %s\n", border("│"), paint(row.Color, text), strings.Repeat(" ", width-visible), border("│"))
	}
	fmt.Printf("  %s\n", border("╰"+strings.Repeat("─", width+2)+"╯"))
}
func generateCertificate(certPath, keyPath string) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", err
	}
	tmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Shah Tunnel Hub"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return "", err
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return "", err
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600); err != nil {
		return "", err
	}
	if err = os.Chmod(keyPath, 0600); err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
func wizardConfigureDNSFilter(c *Config) error {
	if !wizardYesNo("Enable best-effort DNS ad/tracker filtering? (Y/n)", "n") {
		return nil
	}
	return wizardAskDNSFilterSettings(c)
}

func wizardAskDNSFilterSettings(c *Config) error {
	c.DNSFilterEnabled = true
	c.DNSFilterListen = wizardAsk("DNS filter bind address (UDP and TCP)", "0.0.0.0:53")
	c.DNSFilterUpstream = wizardAsk("Upstream DNS server (IP:PORT)", "1.1.1.1:53")
	allowed := wizardAsk("Allowed client source IP/CIDR (required; comma-separated; use the real VPN subnet or client public IP/32)", "")
	c.DNSFilterAllowedCIDRs = nil
	for _, item := range strings.Split(allowed, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, network, err := net.ParseCIDR(item)
		if err != nil {
			return fmt.Errorf("invalid allowed client IP/CIDR %q", item)
		}
		ones, bits := network.Mask.Size()
		if ones == 0 && bits > 0 {
			return fmt.Errorf("refusing unrestricted DNS CIDR %q; do not expose an open DNS resolver", item)
		}
		c.DNSFilterAllowedCIDRs = append(c.DNSFilterAllowedCIDRs, item)
	}
	if len(c.DNSFilterAllowedCIDRs) == 0 {
		return errors.New("DNS filtering was selected but no allowed source IP/CIDR was provided; setup stopped to avoid creating an open resolver")
	}
	uiInfo("DNS filter will listen on " + c.DNSFilterListen + " (UDP/TCP). Permit UDP and TCP on that port in the firewall only for the allowed client networks.")
	uiWarn("Clients must explicitly use this DNS listener and their source IP must match the allowlist. ShahTunnel's TCP reverse tunnel does not assign VPN IPs or automatically route all phone DNS traffic.")
	uiWarn("This blocks known ad/tracker domains, but YouTube in-stream ads may share media domains and cannot be reliably removed by DNS filtering.")
	return nil
}

func manageDNSFilter() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load existing configuration: %w", err)
	}
	defaultChoice := "n"
	if cfg.DNSFilterEnabled {
		defaultChoice = "y"
	}
	if wizardYesNo("Enable DNS ad/tracker filtering? (y/N)", defaultChoice) {
		if err = wizardAskDNSFilterSettings(&cfg); err != nil {
			return err
		}
	} else {
		cfg.DNSFilterEnabled = false
		cfg.DNSFilterListen = ""
		cfg.DNSFilterUpstream = ""
		cfg.DNSFilterAllowedCIDRs = nil
		uiInfo("DNS ad/tracker filtering will be disabled.")
	}
	cfg = normalizeConfig(cfg)
	if err = validateConfig(cfg); err != nil {
		return fmt.Errorf("DNS filter configuration invalid: %w", err)
	}
	if err = saveConfig(cfg); err != nil {
		return fmt.Errorf("save DNS filter configuration: %w", err)
	}
	if err = ensureTunnelRunning(true); err != nil {
		return fmt.Errorf("DNS filter settings saved but service restart failed: %w", err)
	}
	uiSuccess("DNS filter settings saved and service restarted. Existing Hub token and certificate were preserved.")
	return nil
}

func setup() error {
	wizardStep = 0
	uiHeader("SHAH TUNNEL // SPACE SETUP", "WIZARD   •   SECURE LINK   •   TRANSPORT ROUTING")
	uiInfo("Step-by-step setup. Each step asks for one input.")
	if _, err := os.Stat(configPath); err == nil {
		if !wizardYesNo("Overwrite the existing configuration? (y/N)", "n") {
			return errors.New("Setup cancelled; the existing configuration was preserved")
		}
	}

	uiRule()
	fmt.Println(paint(ansiCyan+ansiBold, "  SELECT SERVER ROLE"))
	fmt.Printf("  %s %s\n", paint(ansiGreen+ansiBold, "1"), "🛡️ HUB     | IRAN — accepts Agent connections and exposes public ports")
	fmt.Printf("  %s %s\n", paint(ansiGreen+ansiBold, "2"), "🔗 AGENT   | OUTSIDE — connects securely to Iran and forwards traffic to local services")
	fmt.Printf("  %s %s\n", paint(ansiGreen+ansiBold, "3"), "🌐 RELAY   | THIRD SERVER — public entry point that forwards TCP traffic")
	role := wizardAsk("Select role (1/2/3)", "")
	tok, err := randomHex(32)
	if err != nil {
		return err
	}
	c := Config{Version: version, Token: tok}
	switch role {
	case "1", "hub", "iran":
		c.Role = "hub"
		c.ControlListen = wizardAsk("Agent control listener address", "0.0.0.0:9443")
		c.Transport, err = wizardAskTransport("Hub accepted transport")
		if err != nil {
			return err
		}
		uiInfo("Allow TCP on the control port, control+1 for HTTP/2 CONNECT, and control+2 for HTTP/1.1 CONNECT as selected. Select the same transport policy on both endpoints.")
		c.CertFile, c.KeyFile = "/etc/ravanreverse/hub.crt", "/etc/ravanreverse/hub.key"
		for i := 1; i <= 100; i++ {
			defID := "main"
			if i > 1 {
				defID = fmt.Sprintf("port%d", i)
			}
			id := wizardAsk(fmt.Sprintf("Mapping ID #%d (must match on the Agent)", i), defID)
			listenDefault := "0.0.0.0:443"
			if i > 1 {
				listenDefault = "0.0.0.0:" + strconv.Itoa(8443+i-2)
			}
			addr := wizardAsk(fmt.Sprintf("Public listen address for %s", id), listenDefault)
			c.Ports = append(c.Ports, PortMapping{ID: id, Listen: addr})
			if !wizardYesNo("Add another public port? (y/N)", "n") {
				break
			}
		}
		if err = wizardConfigureDNSFilter(&c); err != nil {
			return err
		}
		c = normalizeConfig(c)
		// Validate before rotating certificate/key files, so a typo cannot invalidate
		// a previously working Hub configuration.
		if err = validateConfig(c); err != nil {
			return err
		}
		fp, e := generateCertificate(c.CertFile, c.KeyFile)
		if e != nil {
			return e
		}
		c.Fingerprint = fp
		if err = saveConfig(c); err != nil {
			return err
		}
		uiRule()
		uiCard("✅ HUB CONFIGURED", []uiCardRow{
			{Text: "Configuration saved successfully.", Color: ansiGreen},
		}, ansiGreen+ansiBold)
		uiCard("🔐 AGENT TOKEN", []uiCardRow{
			{Text: c.Token, Color: ansiYellow + ansiBold},
		}, ansiYellow)
		uiCard("🛡️ CERTIFICATE SHA-256 FINGERPRINT", []uiCardRow{
			{Text: c.Fingerprint, Color: ansiCyan + ansiBold},
		}, ansiCyan)
		uiCard("🔌 CONTROL PORTS", []uiCardRow{
			{Text: "TCP/TLS + WebSocket/TLS: " + portOf(c.ControlListen), Color: ansiPurple + ansiBold},
			{Text: "HTTP/2 CONNECT: " + nextPortLabel(c.ControlListen) + " (TCP)", Color: ansiBlue + ansiBold},
			{Text: "HTTP/1.1 CONNECT: " + secondNextPortLabel(c.ControlListen) + " (TCP)", Color: ansiBlue + ansiBold},
		}, ansiPinkGlow)
		mappingRows := make([]uiCardRow, 0, len(c.Ports))
		for _, p := range c.Ports {
			mappingRows = append(mappingRows, uiCardRow{Text: fmt.Sprintf("ID=%s   LISTEN=%s", p.ID, p.Listen), Color: ansiCyan})
		}
		uiCard("🌐 PUBLIC PORT MAPPINGS", mappingRows, ansiBlue)
		uiCard("⚠️ SECURITY REMINDER", []uiCardRow{
			{Text: "Keep the token secret; enter it only on the Agent.", Color: ansiYellow + ansiBold},
			{Text: "Copy the exact certificate fingerprint into the Agent setup.", Color: ansiDim},
		}, ansiYellow)
		if c.DNSFilterEnabled {
			dnsRows := []uiCardRow{
				{Text: "DNS listener (UDP + TCP): " + c.DNSFilterListen, Color: ansiCyan + ansiBold},
				{Text: "Upstream: " + c.DNSFilterUpstream, Color: ansiDim},
				{Text: "Allowed source CIDRs: " + strings.Join(c.DNSFilterAllowedCIDRs, ", "), Color: ansiYellow},
			}
			uiCard("🧹 DNS AD/TRACKER FILTER ENABLED", dnsRows, ansiGreen+ansiBold)
			uiWarn("Set client DNS to the Hub's reachable IP; ensure UDP and TCP port 53 are allowed only for the listed source networks. This does not automatically route phone DNS through the TCP tunnel.")
		}
	case "2", "agent", "outside":
		c.Role = "agent"
		c.TunnelChannels = defaultTunnelChannels
		c.HubAddr = wizardAsk("Reachable Iran Hub address as IP:PORT or hostname:PORT (control port)", "")
		c.Transport, err = wizardAskTransport("Agent transport mode (must be allowed by Hub)")
		if err != nil {
			return err
		}
		if err = wizardConfigureDNSFilter(&c); err != nil {
			return err
		}
		if transportModeAllowsHTTP2(c.Transport) {
			uiInfo("HTTP/2 CONNECT uses TCP port " + nextPortLabel(c.HubAddr) + ". Open it in the Hub firewall if selected.")
		}
		if transportModeAllowsHTTP1(c.Transport) {
			uiInfo("HTTP/1.1 CONNECT uses TCP port " + secondNextPortLabel(c.HubAddr) + ". Open it in the Hub firewall if selected.")
		}
		c.TLSServerName = wizardAsk("Optional TLS SNI hostname on a domain you control (leave blank to derive from Hub hostname)", "")
		c.Token = wizardAsk("Token shown on the Iran Hub", "")
		c.Fingerprint = wizardAsk("Hub certificate SHA-256 fingerprint", "")
		for i := 1; i <= 100; i++ {
			defID := "main"
			if i > 1 {
				defID = fmt.Sprintf("port%d", i)
			}
			id := wizardAsk(fmt.Sprintf("Mapping ID #%d (must match the Hub)", i), defID)
			targetDefault := "127.0.0.1:443"
			if i > 1 {
				targetDefault = ""
			}
			target := wizardAsk(fmt.Sprintf("Local target for mapping %s on the outside server (IP:PORT)", id), targetDefault)
			if strings.TrimSpace(target) == "" {
				return fmt.Errorf("target for mapping %q is required", id)
			}
			c.Ports = append(c.Ports, PortMapping{ID: id, Target: target})
			if !wizardYesNo("Add another target mapping? (y/N)", "n") {
				break
			}
		}
		c = normalizeConfig(c)
		if err = saveConfig(c); err != nil {
			return err
		}
		_ = os.Remove("/etc/ravanreverse/hub.key")
		_ = os.Remove("/etc/ravanreverse/hub.crt")
		uiInfo(fmt.Sprintf("Performance profile: %d independent tunnel lanes; transport=%s. Option 7 covers TCP/TLS, WebSocket/TLS, HTTP/2 CONNECT, and HTTP/1.1 CONNECT.", c.TunnelChannels, c.Transport))
		uiSuccess("Agent configuration saved. Reconnection is automatic if a lane drops.")
	case "3", "relay", "front":
		c.Role = "relay"
		c.Token = "relay-mode-not-used-" + tok
		if err = wizardConfigureDNSFilter(&c); err != nil {
			return err
		}
		for i := 1; i <= 100; i++ {
			defID := "front"
			if i > 1 {
				defID = fmt.Sprintf("front%d", i)
			}
			id := wizardAsk(fmt.Sprintf("Relay mapping ID #%d", i), defID)
			listenDefault := "0.0.0.0:443"
			if i > 1 {
				listenDefault = "0.0.0.0:" + strconv.Itoa(8443+i-2)
			}
			listen := wizardAsk(fmt.Sprintf("Public client listener for %s", id), listenDefault)
			target := wizardAsk(fmt.Sprintf("Reachable Iran-side target for %s (IP:PORT)", id), "")
			c.Ports = append(c.Ports, PortMapping{ID: id, Listen: listen, Target: target})
			if !wizardYesNo("Add another Relay port? (y/N)", "n") {
				break
			}
		}
		c = normalizeConfig(c)
		if err = saveConfig(c); err != nil {
			return err
		}
		_ = os.Remove("/etc/ravanreverse/hub.key")
		_ = os.Remove("/etc/ravanreverse/hub.crt")
		uiSuccess("Relay configured.")
		uiWarn("Relay changes the client entry point only. The Relay operator and network path may still see the Iran destination IP.")
	default:
		return errors.New("Invalid role. Enter 1 for HUB, 2 for Agent, or 3 for Relay.")
	}
	fmt.Printf("\n  %s %s\n", paint(ansiGreen+ansiBold, "✓"), "Configuration saved: "+configPath)
	uiInfo("Enabling the service and automatic startup after VPS reboot…")
	if err := ensureTunnelRunning(true); err != nil {
		return fmt.Errorf("configuration was saved, but automatic startup failed: %w", err)
	}
	uiSuccess("Tunnel is active and configured to start automatically after reboot.")
	return nil
}

func portOf(addr string) string {
	_, p, e := net.SplitHostPort(addr)
	if e != nil {
		return "?"
	}
	return p
}

func isRoot() bool { return os.Geteuid() == 0 }
func ensureRoot() bool {
	if !isRoot() {
		fmt.Fprintln(os.Stderr, "Run as root.")
		return false
	}
	return true
}
func askYN(prompt string, def string) bool { return strings.EqualFold(ask(prompt, def), "y") }
func runSystemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if len(strings.TrimSpace(string(out))) > 0 {
		fmt.Print(string(out))
		if !strings.HasSuffix(string(out), "\n") {
			fmt.Println()
		}
	}
	return err
}
func tunnelIsActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", "ravanreverse").Run() == nil
}

// ensureTunnelRunning enables boot-time startup and verifies the service really became active.
// restartActive reloads freshly-written configuration when setup was just completed.
func ensureTunnelRunning(restartActive bool) error {
	if !isRoot() {
		return errors.New("run as root")
	}
	if _, err := os.Stat("/etc/systemd/system/ravanreverse.service"); err != nil {
		return errors.New("Shah Tunnel is not installed; run the installer first")
	}
	if err := runSystemctl("enable", "ravanreverse"); err != nil {
		return fmt.Errorf("could not enable automatic startup: %w", err)
	}
	var err error
	if tunnelIsActive() {
		if restartActive {
			err = runSystemctl("restart", "ravanreverse")
		} else {
			fmt.Println("Shah Tunnel is already running.")
		}
	} else {
		// Clear a previous failed/start-limit state so a manual start can recover.
		_ = exec.Command("systemctl", "reset-failed", "ravanreverse").Run()
		err = runSystemctl("start", "ravanreverse")
	}
	if err != nil || !tunnelIsActive() {
		showRecentLogs(40)
		if err != nil {
			return fmt.Errorf("service start/restart failed: %w", err)
		}
		return errors.New("service did not reach active state; recent logs are shown above")
	}
	fmt.Println("Shah Tunnel is active; automatic startup at boot is enabled.")
	return nil
}

func showRecentLogs(n int) {
	out, err := exec.Command("journalctl", "-u", "ravanreverse", "-n", strconv.Itoa(n), "--no-pager", "-o", "short-iso").CombinedOutput()
	if len(out) > 0 {
		fmt.Print(string(out))
	}
	if err != nil {
		fmt.Printf("Could not read service logs: %v\n", err)
	}
}

func showStatusAndLogs() error {
	if _, err := os.Stat("/etc/systemd/system/ravanreverse.service"); err != nil {
		return errors.New("Shah Tunnel is not installed")
	}
	out, err := exec.Command("systemctl", "status", "ravanreverse", "--no-pager", "-l").CombinedOutput()
	if len(out) > 0 {
		fmt.Print(string(out))
	}
	fmt.Println("\n--- Recent service logs ---")
	showRecentLogs(40)
	if err != nil && !tunnelIsActive() {
		return errors.New("service is not active; see logs above")
	}
	return nil
}

const (
	restartScheduleDir    = "/etc/shah-tunnel"
	restartScheduleConfig = "/etc/shah-tunnel/restart.conf"
	restartScheduleState  = "/var/lib/shah-tunnel/last-restart"
	restartCronFile       = "/etc/cron.d/shah-tunnel-restart"
	restartCronScript     = "/usr/local/sbin/shah-tunnel-restart-check"
)

type restartInterval struct {
	label   string
	seconds int64
}

var restartIntervals = []restartInterval{
	{label: "15 minutes", seconds: int64(15 * time.Minute / time.Second)},
	{label: "30 minutes", seconds: int64(30 * time.Minute / time.Second)},
	{label: "50 minutes", seconds: int64(50 * time.Minute / time.Second)},
	{label: "2 hours", seconds: int64(2 * time.Hour / time.Second)},
	{label: "10 hours", seconds: int64(10 * time.Hour / time.Second)},
}

const restartCronScriptBody = `#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
CONFIG="/etc/shah-tunnel/restart.conf"
STATE="/var/lib/shah-tunnel/last-restart"
LOCK="/run/lock/shah-tunnel-restart.lock"
[[ -r "$CONFIG" ]] || exit 0
IFS= read -r INTERVAL < "$CONFIG" || exit 0
[[ "$INTERVAL" =~ ^[0-9]+$ ]] || exit 0
(( INTERVAL > 0 )) || exit 0
command -v flock >/dev/null 2>&1 || exit 0
exec 9>"$LOCK"
flock -n 9 || exit 0
NOW="$(date +%s)"
LAST=""
if [[ -r "$STATE" ]]; then
  IFS= read -r LAST < "$STATE" || LAST=""
fi
if [[ ! "$LAST" =~ ^[0-9]+$ ]] || (( NOW < LAST )); then
  LAST="$NOW"
  printf '%s\n' "$LAST" > "${STATE}.tmp"
  mv -f "${STATE}.tmp" "$STATE"
  exit 0
fi
(( NOW - LAST >= INTERVAL )) || exit 0
if systemctl restart ravanreverse; then
  printf '%s\n' "$NOW" > "${STATE}.tmp"
  mv -f "${STATE}.tmp" "$STATE"
  logger -t shah-tunnel-restart "Shah Tunnel restarted by its configured interval (${INTERVAL}s)." 2>/dev/null || true
else
  logger -t shah-tunnel-restart "Scheduled Shah Tunnel restart failed; it will be retried next minute." 2>/dev/null || true
  exit 1
fi
`

// atomicWriteFile writes a root-owned schedule file by replacing it atomically.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func removeRestartScheduleFiles() error {
	for _, path := range []string{restartCronFile, restartCronScript, restartScheduleConfig, restartScheduleState, restartScheduleConfig + ".tmp", restartScheduleState + ".tmp", restartCronFile + ".tmp", restartCronScript + ".tmp"} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, dir := range []string{restartScheduleDir, "/var/lib/shah-tunnel"} {
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
			return err
		}
	}
	return nil
}

func restartScheduleStatus() string {
	data, err := os.ReadFile(restartScheduleConfig)
	if err != nil {
		return "No scheduled restart"
	}
	cronEntry, err := os.ReadFile(restartCronFile)
	if err != nil || !strings.Contains(string(cronEntry), restartCronScript) {
		return "Incomplete: cron entry is missing or invalid"
	}
	checker, err := os.ReadFile(restartCronScript)
	if err != nil || !strings.Contains(string(checker), "systemctl restart ravanreverse") {
		return "Incomplete: restart checker is missing or invalid"
	}
	state, err := os.ReadFile(restartScheduleState)
	if err != nil {
		return "Incomplete: timer state is missing"
	}
	if _, err := strconv.ParseInt(strings.TrimSpace(string(state)), 10, 64); err != nil {
		return "Incomplete: timer state is invalid"
	}
	if _, err := exec.LookPath("flock"); err != nil {
		return "Configured, but flock is missing"
	}
	cronActive := false
	for _, candidate := range []string{"cron.service", "crond.service"} {
		if exec.Command("systemctl", "is-active", "--quiet", candidate).Run() == nil {
			cronActive = true
			break
		}
	}
	if !cronActive {
		return "Files configured, but cron daemon is inactive"
	}
	seconds, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || seconds <= 0 {
		return "Schedule file is invalid"
	}
	for _, interval := range restartIntervals {
		if seconds == interval.seconds {
			return "Every " + interval.label + " (cron active)"
		}
	}
	return fmt.Sprintf("Every %s (cron active)", time.Duration(seconds)*time.Second)
}

func setRestartSchedule(interval restartInterval) error {
	if !isRoot() {
		return errors.New("run as root")
	}
	if _, err := os.Stat("/etc/systemd/system/ravanreverse.service"); err != nil {
		return errors.New("Shah Tunnel is not installed; install it before setting a restart schedule")
	}
	if _, err := os.Stat("/etc/cron.d"); err != nil {
		return errors.New("/etc/cron.d is unavailable; this scheduler supports Debian/Ubuntu-style cron")
	}
	if _, err := exec.LookPath("flock"); err != nil {
		return errors.New("flock is required (normally supplied by util-linux)")
	}
	if _, err := os.Stat("/usr/sbin/cron"); err != nil {
		if _, lookErr := exec.LookPath("crond"); lookErr != nil {
			return errors.New("cron daemon is not installed; install the cron package and try again")
		}
	}
	cronService := ""
	for _, candidate := range []string{"cron.service", "crond.service"} {
		if exec.Command("systemctl", "cat", candidate).Run() == nil {
			cronService = candidate
			break
		}
	}
	if cronService == "" {
		return errors.New("systemd cron service unit was not found; start/enable cron and try again")
	}
	if exec.Command("systemctl", "is-active", "--quiet", cronService).Run() != nil {
		if out, err := exec.Command("systemctl", "enable", "--now", cronService).CombinedOutput(); err != nil {
			return fmt.Errorf("could not start cron daemon: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err := atomicWriteFile(restartScheduleState, []byte(strconv.FormatInt(time.Now().Unix(), 10)+"\n"), 0600); err != nil {
		return fmt.Errorf("initialize schedule timer: %w", err)
	}
	if err := atomicWriteFile(restartScheduleConfig, []byte(strconv.FormatInt(interval.seconds, 10)+"\n"), 0600); err != nil {
		return fmt.Errorf("write schedule configuration: %w", err)
	}
	if err := atomicWriteFile(restartCronScript, []byte(restartCronScriptBody), 0750); err != nil {
		return fmt.Errorf("write restart checker: %w", err)
	}
	cron := "SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n* * * * * root " + restartCronScript + " >/dev/null 2>&1\n"
	if err := atomicWriteFile(restartCronFile, []byte(cron), 0644); err != nil {
		return fmt.Errorf("write cron entry: %w", err)
	}
	fmt.Printf("\n  ✓ Scheduled restart enabled: every %s. The first restart is after the selected interval.\n", interval.label)
	fmt.Println("  Warning: each scheduled restart interrupts active tunnel connections; cron timing is accurate to about one minute.")
	return nil
}

func manageRestartSchedule() error {
	if !ensureRoot() {
		return errors.New("root permissions are required")
	}
	for {
		uiRule()
		fmt.Println(paint(ansiCyan+ansiBold, "  CRON JOB / SCHEDULED RESTART"))
		fmt.Printf("  %s %s\n", paint(ansiDim, "CURRENT"), paint(ansiYellow, restartScheduleStatus()))
		fmt.Println("  [1]  Restart every 15 minutes")
		fmt.Println("  [2]  Restart every 30 minutes")
		fmt.Println("  [3]  Restart every 50 minutes")
		fmt.Println("  [4]  Restart every 2 hours")
		fmt.Println("  [5]  Restart every 10 hours")
		fmt.Println("  [6]  Remove scheduled restart")
		fmt.Println("  [0]  Back to main menu")
		choice := ask("Select a schedule", "0")
		if choice == "0" {
			return nil
		}
		if choice == "6" {
			if err := removeRestartScheduleFiles(); err != nil {
				return fmt.Errorf("remove schedule: %w", err)
			}
			fmt.Println("Scheduled restart removed. Shah Tunnel will no longer be restarted by this cron job.")
			continue
		}
		idx, err := strconv.Atoi(choice)
		if err != nil || idx < 1 || idx > len(restartIntervals) {
			fmt.Println("Invalid selection.")
			continue
		}
		if err := setRestartSchedule(restartIntervals[idx-1]); err != nil {
			return err
		}
	}
}

var errUninstallCancelled = errors.New("uninstall cancelled")

func uninstall() error {
	fmt.Println("This permanently removes only Shah Tunnel files and its own service.")
	fmt.Println("Xray, x-ui, other services and manually-created firewall rules are left untouched.")
	if ask("Type DELETE SHAH TUNNEL to confirm complete removal", "") != "DELETE SHAH TUNNEL" {
		fmt.Println("Cancelled.")
		return errUninstallCancelled
	}

	// Stop and disable only this unit. Do not remove files while systemd still
	// reports the unit as active/deactivating.
	_ = exec.Command("systemctl", "disable", "ravanreverse").Run()
	_ = exec.Command("systemctl", "stop", "ravanreverse").Run()
	state := func() string {
		b, _ := exec.Command("systemctl", "show", "ravanreverse", "-p", "ActiveState", "--value").Output()
		return strings.TrimSpace(string(b))
	}
	for i := 0; i < 20; i++ {
		s := state()
		if s == "" || s == "inactive" || s == "failed" || s == "unknown" || s == "dead" {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	s := state()
	if s == "active" || s == "deactivating" || s == "activating" || s == "reloading" {
		// Last-resort signal is scoped to the Shah Tunnel systemd unit only.
		_ = exec.Command("systemctl", "kill", "--kill-who=all", "--signal=KILL", "ravanreverse").Run()
		_ = exec.Command("systemctl", "stop", "ravanreverse").Run()
		time.Sleep(500 * time.Millisecond)
		s = state()
	}
	if s == "active" || s == "deactivating" || s == "activating" || s == "reloading" {
		return fmt.Errorf("service would not stop (state=%s); files were kept. Check: systemctl status ravanreverse", s)
	}
	if err := removeRestartScheduleFiles(); err != nil {
		return fmt.Errorf("remove Shah Tunnel restart schedule: %w", err)
	}

	if err := os.Remove("/etc/systemd/system/ravanreverse.service"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove service unit: %w", err)
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemd daemon-reload failed: %v %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("systemctl", "reset-failed", "ravanreverse").Run()
	for _, path := range []string{"/etc/ravanreverse", "/usr/local/bin/ravanreverse", "/usr/local/bin/shah-tunnel", "/var/backups/ravanreverse", "/var/log/ravanreverse"} {
		if err := os.RemoveAll(path); err != nil {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	if askYN("Also remove known old Shah Tunnel installer files under /root? [y/N]", "n") {
		for _, path := range []string{
			"/root/RavanReverse-1.0.0", "/root/RavanReverse-1.1.0", "/root/RavanReverse-1.2.0", "/root/RavanReverse-1.3.0", "/root/RavanReverse-1.3.1", "/root/RavanReverse-1.3.2", "/root/Shah-Tunnel-1.3.3",
			"/root/RavanReverse-1.0.0-Linux-amd64.zip", "/root/RavanReverse-1.1.0-Linux-amd64.zip", "/root/RavanReverse-1.2.0-Linux-amd64.zip", "/root/RavanReverse-1.3.0-Linux-amd64.zip", "/root/RavanReverse-1.3.1-Linux-amd64.zip", "/root/RavanReverse-1.3.2-Linux-amd64.zip", "/root/Shah-Tunnel-1.3.3-Linux-amd64.zip",
			"/root/RavanReverse-1.1.0-Linux-amd64.zip.sha256", "/root/RavanReverse-1.2.0-Linux-amd64.zip.sha256", "/root/RavanReverse-1.3.0-Linux-amd64.zip.sha256", "/root/RavanReverse-1.3.1-Linux-amd64.zip.sha256", "/root/RavanReverse-1.3.2-Linux-amd64.zip.sha256", "/root/Shah-Tunnel-1.3.3-Linux-amd64.zip.sha256",
		} {
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("remove installer path %s: %w", path, err)
			}
		}
	}
	fmt.Println("Shah Tunnel service, binary and configuration have been removed.")
	fmt.Println("Xray/x-ui and unrelated firewall/proxy settings were not changed.")
	return nil
}

// ServerGeo caches the server's public IPv4 address and its GeoIP country.
// IP discovery is independent from GeoIP: if all GeoIP services are blocked,
// a valid IPv4 can still be shown while country is reported as Unknown.
// Public IPs are sent to the selected third-party IP/GeoIP provider.
type ServerGeo struct {
	IP          string    `json:"ip"`
	Country     string    `json:"country_name"`
	CountryCode string    `json:"country_code"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastAttempt time.Time `json:"last_attempt"`
	Valid       bool      `json:"valid"`
}

const serverGeoCachePath = "/etc/ravanreverse/server-info-v2.json"

const (
	geoFailureRetryInterval = 45 * time.Second
	geoCacheTTL             = 6 * time.Hour
	geoRequestTimeout       = 2200 * time.Millisecond
)

func normalizeServerGeo(g ServerGeo) ServerGeo {
	rawIP := strings.TrimSpace(g.IP)
	if rawIP == "" {
		g.Valid = false
		return g
	}
	parsed := net.ParseIP(rawIP)
	if parsed == nil || parsed.To4() == nil {
		// The menu is deliberately IPv4-only. Invalidate old IPv6/bad cache
		// entries and force a fresh lookup instead of showing stale geography.
		g.IP = ""
		g.Country = ""
		g.CountryCode = ""
		g.UpdatedAt = time.Time{}
		g.LastAttempt = time.Time{}
		g.Valid = false
		return g
	}
	g.IP = parsed.To4().String()
	return g
}

func readServerGeoCache() ServerGeo {
	var g ServerGeo
	b, err := os.ReadFile(serverGeoCachePath)
	if err == nil {
		_ = json.Unmarshal(b, &g)
	}
	return normalizeServerGeo(g)
}

func writeServerGeoCache(g ServerGeo) {
	if err := os.MkdirAll("/etc/ravanreverse", 0700); err != nil {
		return
	}
	b, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return
	}
	tmp := serverGeoCachePath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, serverGeoCachePath); err != nil {
		_ = os.Remove(tmp)
		return
	}
	_ = os.Chmod(serverGeoCachePath, 0600)
}

// isPublicIPv4 rejects private, local, shared-CGNAT, documentation, benchmark,
// multicast and reserved IPv4 space. Interface addresses are preferred because
// they require no external service and continue to work on filtered networks.
func isPublicIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil || v4.IsPrivate() || v4.IsLoopback() || v4.IsLinkLocalUnicast() || v4.IsMulticast() || v4.IsUnspecified() {
		return false
	}
	a, b, c := v4[0], v4[1], v4[2]
	if a == 0 || a >= 240 || (a == 100 && b >= 64 && b <= 127) ||
		(a == 192 && b == 0 && c == 0) || (a == 192 && b == 0 && c == 2) ||
		(a == 198 && (b == 18 || b == 19)) || (a == 198 && b == 51 && c == 100) ||
		(a == 203 && b == 0 && c == 113) {
		return false
	}
	return true
}

// detectAssignedPublicIPv4 finds an IPv4 assigned directly to the active route
// first. It deliberately refuses private/interface-local addresses, which are
// not the public identity the menu should advertise.
func detectAssignedPublicIPv4() string {
	var routeDev string
	if out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output(); err == nil {
		fields := strings.Fields(string(out))
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "src" {
				if parsed := net.ParseIP(fields[i+1]); isPublicIPv4(parsed) {
					return parsed.To4().String()
				}
			}
			if fields[i] == "dev" {
				routeDev = fields[i+1]
			}
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	// Check the route interface before other interfaces, to avoid selecting an
	// address from an unrelated or dormant interface when possible.
	if routeDev != "" {
		for _, iface := range interfaces {
			if iface.Name == routeDev {
				if ip := publicIPv4OnInterface(iface); ip != "" {
					return ip
				}
				break
			}
		}
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Name == routeDev {
			continue
		}
		if ip := publicIPv4OnInterface(iface); ip != "" {
			return ip
		}
	}
	return ""
}

func publicIPv4OnInterface(iface net.Interface) string {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch a := addr.(type) {
		case *net.IPNet:
			ip = a.IP
		case *net.IPAddr:
			ip = a.IP
		}
		if isPublicIPv4(ip) {
			return ip.To4().String()
		}
	}
	return ""
}

func geoHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		// Do not silently use an HTTP_PROXY/HTTPS_PROXY setting: that would
		// identify the proxy's address instead of the server's public address.
		Proxy: nil,
		DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func fetchGeoFromURL(ctx context.Context, client *http.Client, rawURL, expectedIP string) (ServerGeo, bool) {
	var zero ServerGeo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return zero, false
	}
	req.Header.Set("User-Agent", "ShahTunnel/"+version)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return zero, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return zero, false
	}
	return parseGeoResponse(body, expectedIP)
}

func parseGeoResponse(body []byte, expectedIP string) (ServerGeo, bool) {
	var zero ServerGeo
	var result struct {
		IP          string `json:"ip"`
		Query       string `json:"query"`
		CountryName string `json:"country_name"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		CodeCamel   string `json:"countryCode"`
		Status      string `json:"status"`
		Success     *bool  `json:"success"`
	}
	if err := json.Unmarshal(body, &result); err != nil || strings.EqualFold(result.Status, "fail") || (result.Success != nil && !*result.Success) {
		return zero, false
	}
	returnedIP := strings.TrimSpace(result.IP)
	if returnedIP == "" {
		returnedIP = strings.TrimSpace(result.Query)
	}
	if expectedIP != "" {
		expected := net.ParseIP(expectedIP)
		if expected == nil || expected.To4() == nil {
			return zero, false
		}
		if returnedIP != "" {
			got := net.ParseIP(returnedIP)
			if got == nil || got.To4() == nil || !got.To4().Equal(expected.To4()) {
				return zero, false
			}
		}
		returnedIP = expected.To4().String()
	}
	parsedIP := net.ParseIP(returnedIP)
	if !isPublicIPv4(parsedIP) {
		return zero, false
	}

	country := strings.TrimSpace(result.CountryName)
	code := strings.ToUpper(strings.TrimSpace(result.CountryCode))
	if code == "" {
		code = strings.ToUpper(strings.TrimSpace(result.CodeCamel))
	}
	if country == "" {
		countryValue := strings.TrimSpace(result.Country)
		if isAlphaCountryCode(countryValue) {
			if code == "" {
				code = strings.ToUpper(countryValue)
			}
		} else {
			country = countryValue
		}
	}
	if country == "" && code != "" {
		country = countryNameFromCode(code)
	}
	if country == "" {
		country = "Unknown"
	}
	if strings.EqualFold(country, "Unknown") {
		code = ""
	}
	return ServerGeo{IP: parsedIP.To4().String(), Country: country, CountryCode: code, UpdatedAt: time.Now(), Valid: true}, true
}

func isAlphaCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		c := s[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func countryNameFromCode(code string) string {
	// Common fallback names for code-only providers such as ipinfo.io. Country
	// name remains Unknown for codes we cannot map instead of guessing location.
	names := map[string]string{
		"IR": "Iran", "DE": "Germany", "US": "United States", "GB": "United Kingdom",
		"NL": "Netherlands", "FR": "France", "TR": "Türkiye", "RU": "Russia",
		"CA": "Canada", "SG": "Singapore", "FI": "Finland", "SE": "Sweden",
		"CH": "Switzerland", "AT": "Austria", "AE": "United Arab Emirates",
		"SA": "Saudi Arabia", "CN": "China", "JP": "Japan", "IN": "India",
		"IT": "Italy", "ES": "Spain", "PL": "Poland", "BE": "Belgium",
		"CZ": "Czechia", "DK": "Denmark", "NO": "Norway", "UA": "Ukraine",
		"RO": "Romania", "BG": "Bulgaria", "GR": "Greece", "CY": "Cyprus",
		"HK": "Hong Kong", "KR": "South Korea", "TW": "Taiwan", "ID": "Indonesia",
		"MY": "Malaysia", "TH": "Thailand", "BR": "Brazil", "AU": "Australia",
	}
	return names[strings.ToUpper(strings.TrimSpace(code))]
}

func lookupGeoURLs(urls []string, expectedIP string, returnIPOnly bool) (ServerGeo, bool) {
	var zero ServerGeo
	client := geoHTTPClient(geoRequestTimeout)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
	defer cancel()
	type answer struct {
		geo ServerGeo
		ok  bool
	}
	results := make(chan answer, len(urls))
	for _, rawURL := range urls {
		url := rawURL
		go func() {
			g, ok := fetchGeoFromURL(ctx, client, url, expectedIP)
			select {
			case results <- answer{geo: g, ok: ok}:
			case <-ctx.Done():
			}
		}()
	}
	var ipOnly ServerGeo
	for range urls {
		select {
		case got := <-results:
			if !got.ok || !got.geo.Valid {
				continue
			}
			if got.geo.Country != "" && !strings.EqualFold(got.geo.Country, "Unknown") {
				return got.geo, true
			}
			if !ipOnly.Valid {
				ipOnly = got.geo
			}
		case <-ctx.Done():
			if returnIPOnly && ipOnly.Valid {
				return ipOnly, true
			}
			return zero, false
		}
	}
	if returnIPOnly && ipOnly.Valid {
		return ipOnly, true
	}
	return zero, false
}

func detectPublicIPv4FromAPIs() string {
	urls := []string{
		"https://api.ipify.org/",
		"https://ipv4.icanhazip.com/",
		"https://checkip.amazonaws.com/",
		"https://ipinfo.io/ip",
		"https://api.ip.sb/ip",
	}
	client := geoHTTPClient(geoRequestTimeout)
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2600*time.Millisecond)
	defer cancel()
	type answer struct{ ip string }
	results := make(chan answer, len(urls))
	for _, rawURL := range urls {
		url := rawURL
		go func() {
			var got answer
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err == nil {
				req.Header.Set("User-Agent", "ShahTunnel/"+version)
				resp, reqErr := client.Do(req)
				if reqErr == nil {
					if resp.StatusCode == http.StatusOK {
						body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
						ip := net.ParseIP(strings.TrimSpace(string(body)))
						if isPublicIPv4(ip) {
							got.ip = ip.To4().String()
						}
					}
					_ = resp.Body.Close()
				}
			}
			select {
			case results <- got:
			case <-ctx.Done():
			}
		}()
	}
	for range urls {
		select {
		case got := <-results:
			if got.ip != "" {
				return got.ip
			}
		case <-ctx.Done():
			return ""
		}
	}
	return ""
}

func lookupCountryForIPv4(ip string) (ServerGeo, bool) {
	urls := []string{
		"https://ipapi.co/" + ip + "/json/",
		"https://ipwho.is/" + ip,
		"https://api.ip.sb/geoip/" + ip,
		"https://ipinfo.io/" + ip + "/json",
	}
	return lookupGeoURLs(urls, ip, false)
}

func lookupCombinedServerGeo() (ServerGeo, bool) {
	urls := []string{
		"https://ipapi.co/json/",
		"https://ipwho.is/",
		"https://ipinfo.io/json",
	}
	return lookupGeoURLs(urls, "", true)
}

func serverIdentity() (string, string) {
	g := readServerGeoCache()
	now := time.Now()
	if !g.LastAttempt.IsZero() && now.Sub(g.LastAttempt) >= 0 && now.Sub(g.LastAttempt) < geoFailureRetryInterval {
		return geoDisplay(g)
	}
	if g.Valid && g.Country != "" && !strings.EqualFold(g.Country, "Unknown") && !g.UpdatedAt.IsZero() && now.Sub(g.UpdatedAt) >= 0 && now.Sub(g.UpdatedAt) < geoCacheTTL {
		return geoDisplay(g)
	}

	g.LastAttempt = now
	ip := detectAssignedPublicIPv4()
	var combined ServerGeo
	var combinedOK bool
	if ip == "" {
		// For NAT/private-interface VPSs, discover the public IPv4 through
		// multiple providers. One blocked provider must not blank the menu.
		combined, combinedOK = lookupCombinedServerGeo()
		if combinedOK {
			ip = combined.IP
		}
		if ip == "" {
			ip = detectPublicIPv4FromAPIs()
		}
	}

	if ip == "" {
		// Keep a previously verified IPv4 visible during a temporary API/network
		// outage instead of replacing it with Unavailable.
		if g.Valid && g.IP != "" {
			g.LastAttempt = now
			writeServerGeoCache(g)
			return geoDisplay(g)
		}
		g.Valid = false
		g.LastAttempt = now
		writeServerGeoCache(g)
		return geoDisplay(g)
	}

	next := ServerGeo{IP: ip, Valid: true, UpdatedAt: now, LastAttempt: now}
	if combinedOK && combined.IP == ip && combined.Country != "" && !strings.EqualFold(combined.Country, "Unknown") {
		next.Country = combined.Country
		next.CountryCode = combined.CountryCode
		next.UpdatedAt = combined.UpdatedAt
	} else if countryGeo, ok := lookupCountryForIPv4(ip); ok && countryGeo.Country != "" && !strings.EqualFold(countryGeo.Country, "Unknown") {
		next.Country = countryGeo.Country
		next.CountryCode = countryGeo.CountryCode
		next.UpdatedAt = countryGeo.UpdatedAt
	} else if g.Valid && g.IP == ip {
		// A transient GeoIP outage should not erase a previously correct country.
		next.Country = g.Country
		next.CountryCode = g.CountryCode
		next.UpdatedAt = g.UpdatedAt
	}
	writeServerGeoCache(next)
	return geoDisplay(next)
}

func geoDisplay(g ServerGeo) (string, string) {
	g = normalizeServerGeo(g)
	if !g.Valid || strings.TrimSpace(g.IP) == "" {
		return "Unavailable", "Unknown"
	}
	country := strings.TrimSpace(g.Country)
	if country == "" || strings.EqualFold(country, "Unknown") {
		country = "Unknown"
	} else if g.CountryCode != "" && !strings.EqualFold(country, g.CountryCode) {
		country += " (" + g.CountryCode + ")"
	}
	if !g.UpdatedAt.IsZero() && time.Since(g.UpdatedAt) > geoCacheTTL {
		if country == "Unknown" {
			country = "Unknown [cached IP]"
		} else {
			country += " [cached]"
		}
	}
	return g.IP, country
}
func menu() {
	if !ensureRoot() {
		return
	}
	for {
		state := paint(ansiYellow, "○ OFFLINE / NOT CONFIGURED")
		if tunnelIsActive() {
			state = paint(ansiGreen+ansiBold, "● ONLINE")
		}
		uiHeader("SHAH TUNNEL // COMMAND DECK", "SPACE NETWORK   •   ENCRYPTED CONTROL   •   TCP TUNNEL")
		fmt.Printf("  %s %s\n", paint(ansiDim, "VERSION"), paint(ansiCyan, version+"  |  "+runtimeArch()))
		fmt.Printf("  %s %s\n", paint(ansiDim, "LINK STATUS"), state)
		serverIP, serverCountry := serverIdentity()
		fmt.Printf("  %s %s\n", paint(ansiDim, "🌐 SERVER IP"), paint(ansiCyan, serverIP))
		fmt.Printf("  %s %s\n", paint(ansiDim, "🌍 COUNTRY"), paint(ansiCyan, serverCountry))
		uiRule()
		fmt.Println(paint(ansiCyan+ansiBold, "  OPERATIONS"))
		menuItem := func(key, title, desc string) {
			fmt.Printf("  %s  %s %s\n", paint(ansiPurple+ansiBold, "["+key+"]"), paint(ansiBold, fmt.Sprintf("%-32s", title)), paint(ansiDim, desc))
		}
		menuItem("1", "🛠️ Configure / Create Tunnel", "Step-by-step setup wizard")
		menuItem("2", "🚀 Start Tunnel", "Start the service")
		menuItem("3", "🛑 Stop Tunnel", "Stop the running service")
		menuItem("4", "🔄 Restart Tunnel", "Reload saved configuration")
		menuItem("5", "📊 Status & Logs", "Service status and recent errors")
		menuItem("6", "⏱️ Cron Job / Scheduled Restart", "Restart every selected interval")
		menuItem("7", "🗑️ Complete Uninstall", "Only Shah Tunnel files and service")
		menuItem("8", "🧹 DNS Ad/Tracker Filter", "Enable/disable DNS filtering without regenerating Hub credentials")
		menuItem("0", "🚪 Exit", "Close the menu")
		uiRule()
		choice := ask("Select an operation", "0")
		var err error
		switch choice {
		case "1":
			err = setup() // setup starts/restarts the service automatically on success
		case "2":
			err = ensureTunnelRunning(false)
		case "3":
			err = runSystemctl("stop", "ravanreverse")
			if err == nil && tunnelIsActive() {
				err = errors.New("service is still active after stop")
			}
		case "4":
			err = ensureTunnelRunning(true)
		case "5":
			err = showStatusAndLogs()
		case "6":
			err = manageRestartSchedule()
		case "7":
			err = uninstall()
			if err == nil {
				return
			}
			if errors.Is(err, errUninstallCancelled) {
				err = nil
			}
		case "8":
			err = manageDNSFilter()
		case "0":
			return
		default:
			err = errors.New("Invalid option")
		}
		if err != nil {
			fmt.Printf("\n  %s %s\n", paint(ansiRed+ansiBold, "✗ ERROR:"), err)
		}
		if choice != "7" {
			_ = ask("Press Enter to return to the menu", "")
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cmd := "menu"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "setup":
		if !ensureRoot() {
			os.Exit(1)
		}
		if err := setup(); err != nil {
			log.Fatal(err)
		}
	case "menu":
		menu()
	case "run":
		cfg, err := loadConfig()
		if err != nil {
			log.Fatal(err)
		}
		if err = startDNSAdFilter(cfg); err != nil {
			// DNS filtering is optional and must never prevent the tunnel itself from starting.
			log.Printf("DNS ad filter could not start; continuing without DNS filtering: %v", err)
		}
		switch cfg.Role {
		case "hub":
			err = runHub(cfg)
		case "agent":
			err = runAgent(cfg)
		case "relay":
			err = runRelay(cfg)
		default:
			err = fmt.Errorf("unsupported role %q", cfg.Role)
		}
		if err != nil {
			log.Fatal(err)
		}
	case "uninstall":
		if !ensureRoot() {
			os.Exit(1)
		}
		if err := uninstall(); err != nil {
			log.Fatal(err)
		}
	case "version", "--version", "-v":
		fmt.Printf("Shah Tunnel %s (%s)\n", version, runtimeArch())
	default:
		fmt.Printf("Shah Tunnel %s\nUsage: shah-tunnel [menu|setup|run|uninstall|version]\n", version)
	}
}

func runtimeArch() string { return runtime.GOOS + "/" + runtime.GOARCH }
