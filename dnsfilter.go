package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// dnsAdFilter is a best-effort DNS sinkhole. It does not inspect HTTPS content
// and cannot reliably remove YouTube in-stream ads served from shared domains.
type dnsAdFilter struct {
	listen   string
	upstream string
	allowed  []net.IPNet
	mu       sync.RWMutex
	blocked  map[string]struct{}
	rateMu   sync.Mutex
	rates    map[string]dnsRateEntry
}

type dnsRateEntry struct {
	window time.Time
	count  int
}

var builtinAdDomains = []string{
	"doubleclick.net", "googlesyndication.com", "googleadservices.com",
	"googleadservices.com", "adservice.google.com", "adtrafficquality.google",
	"securepubads.g.doubleclick.net", "pagead2.googlesyndication.com",
	"adnxs.com", "adsrvr.org", "criteo.com", "taboola.com", "outbrain.com",
	"scorecardresearch.com", "amazon-adsystem.com", "serving-sys.com",
	"smartadserver.com", "rubiconproject.com", "openx.net", "pubmatic.com",
	"casalemedia.com", "contextweb.com", "yieldmo.com", "bidswitch.net",
	"sharethrough.com", "adform.net", "adcolony.com", "unityads.unity3d.com",
	"applovin.com", "inmobi.com", "mopub.com", "adsafeprotected.com",
	"moatads.com", "demdex.net", "bluekai.com", "rlcdn.com", "quantserve.com",
	"zedo.com", "advertising.com", "adroll.com", "serving-sys.com",
}

func newDNSAdFilter(c Config) (*dnsAdFilter, error) {
	f := &dnsAdFilter{
		listen: c.DNSFilterListen, upstream: c.DNSFilterUpstream,
		blocked: make(map[string]struct{}, 4096), rates: make(map[string]dnsRateEntry),
	}
	for _, cidr := range c.DNSFilterAllowedCIDRs {
		_, block, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("invalid DNS filter CIDR %q: %w", cidr, err)
		}
		f.allowed = append(f.allowed, *block)
	}
	if len(f.allowed) == 0 {
		return nil, errors.New("DNS ad filter has no client allowlist; refusing to start an open DNS resolver")
	}
	for _, d := range builtinAdDomains {
		f.blocked[strings.ToLower(strings.TrimSpace(d))] = struct{}{}
	}
	return f, nil
}

// bindDNSListeners first tries the requested address. If a wildcard :53 bind
// conflicts with a local stub resolver (common on Linux), it retries on each
// non-loopback interface address instead of disabling the filter altogether.
func bindDNSListeners(address string) ([]net.PacketConn, []net.Listener, error) {
	udp, udpErr := net.ListenPacket("udp", address)
	if udpErr == nil {
		tcp, tcpErr := net.Listen("tcp", address)
		if tcpErr == nil {
			return []net.PacketConn{udp}, []net.Listener{tcp}, nil
		}
		_ = udp.Close()
		udpErr = tcpErr
	}

	host, port, splitErr := net.SplitHostPort(address)
	if splitErr != nil || (host != "" && host != "0.0.0.0" && host != "::" && host != "[::]") {
		return nil, nil, fmt.Errorf("UDP/TCP bind failed: %w", udpErr)
	}

	var udpListeners []net.PacketConn
	var tcpListeners []net.Listener
	seen := make(map[string]struct{})
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("wildcard bind failed (%v); enumerate interfaces: %w", udpErr, err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			var ip net.IP
			switch v := raw.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.To4() != nil {
				ip = ip.To4()
			} else {
				ip = ip.To16()
			}
			if ip == nil {
				continue
			}
			bindAddr := net.JoinHostPort(ip.String(), port)
			if _, ok := seen[bindAddr]; ok {
				continue
			}
			seen[bindAddr] = struct{}{}
			u, uErr := net.ListenPacket("udp", bindAddr)
			if uErr != nil {
				continue
			}
			t, tErr := net.Listen("tcp", bindAddr)
			if tErr != nil {
				_ = u.Close()
				continue
			}
			udpListeners = append(udpListeners, u)
			tcpListeners = append(tcpListeners, t)
		}
	}
	if len(udpListeners) == 0 || len(tcpListeners) == 0 {
		for _, l := range udpListeners {
			_ = l.Close()
		}
		for _, l := range tcpListeners {
			_ = l.Close()
		}
		return nil, nil, fmt.Errorf("wildcard bind failed (%v) and no interface address could bind both UDP and TCP on port %s", udpErr, port)
	}
	addresses := make([]string, 0, len(udpListeners))
	for _, l := range udpListeners {
		addresses = append(addresses, l.LocalAddr().String())
	}
	log.Printf("DNS wildcard bind conflicted with another listener; bound on interface addresses: %s", strings.Join(addresses, ", "))
	return udpListeners, tcpListeners, nil
}

func startDNSAdFilter(c Config) error {
	if !c.DNSFilterEnabled {
		return nil
	}
	f, err := newDNSAdFilter(c)
	if err != nil {
		return err
	}
	udpListeners, tcpListeners, err := bindDNSListeners(f.listen)
	if err != nil {
		return fmt.Errorf("start DNS ad filter listeners at %s: %w", f.listen, err)
	}
	log.Printf("best-effort DNS ad/tracker filter listening on %s (allowlisted sources only); YouTube in-stream ads are not guaranteed to be blocked", f.listen)
	for _, listener := range udpListeners {
		go f.serveUDP(listener)
	}
	for _, listener := range tcpListeners {
		go f.serveTCP(listener)
	}
	go f.refreshLoop()
	return nil
}

func (f *dnsAdFilter) allowedSource(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range f.allowed {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Limit each allowlisted source to 60 DNS questions per second to avoid a
// single misconfigured client exhausting the small VPS.
func (f *dnsAdFilter) rateAllowed(addr net.Addr) bool {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	now := time.Now()
	f.rateMu.Lock()
	defer f.rateMu.Unlock()
	entry := f.rates[host]
	if now.Sub(entry.window) >= time.Second || entry.window.IsZero() {
		entry = dnsRateEntry{window: now, count: 0}
	}
	entry.count++
	f.rates[host] = entry
	if len(f.rates) > 4096 {
		for ip, e := range f.rates {
			if now.Sub(e.window) > time.Minute {
				delete(f.rates, ip)
			}
		}
	}
	return entry.count <= 60
}

func (f *dnsAdFilter) isBlocked(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	f.mu.RLock()
	defer f.mu.RUnlock()
	for domain != "" {
		if _, ok := f.blocked[domain]; ok {
			return true
		}
		i := strings.IndexByte(domain, '.')
		if i < 0 {
			break
		}
		domain = domain[i+1:]
	}
	return false
}

func (f *dnsAdFilter) serveUDP(pc net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		if !f.allowedSource(addr) || !f.rateAllowed(addr) {
			continue
		}
		go func(addr net.Addr, query []byte) {
			response, err := f.handleQuery(query, "udp")
			if err != nil {
				response = dnsErrorResponse(query, 2)
			}
			if len(response) > 1232 {
				response = dnsTruncatedResponse(response)
			}
			if len(response) > 0 {
				_, _ = pc.WriteTo(response, addr)
			}
		}(addr, query)
	}
}

func (f *dnsAdFilter) serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go f.handleTCPConn(conn)
	}
}

func (f *dnsAdFilter) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !f.allowedSource(conn.RemoteAddr()) {
		return
	}
	for {
		var size [2]byte
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 || n > 4096 {
			return
		}
		query := make([]byte, n)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		if !f.rateAllowed(conn.RemoteAddr()) {
			return
		}
		response, err := f.handleQuery(query, "tcp")
		if err != nil {
			response = dnsErrorResponse(query, 2)
		}
		if len(response) > 4096 {
			response = dnsTruncatedResponse(response)
		}
		if len(response) == 0 {
			return
		}
		binary.BigEndian.PutUint16(size[:], uint16(len(response)))
		if _, err := conn.Write(size[:]); err != nil {
			return
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

func dnsQuestionName(msg []byte) (string, int, error) {
	if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return "", 0, errors.New("DNS packet must contain exactly one question")
	}
	i := 12
	labels := make([]string, 0, 8)
	for {
		if i >= len(msg) {
			return "", 0, errors.New("truncated DNS name")
		}
		l := int(msg[i])
		i++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || l > 63 || i+l > len(msg) {
			return "", 0, errors.New("invalid or compressed DNS question name")
		}
		labels = append(labels, strings.ToLower(string(msg[i:i+l])))
		i += l
		if len(labels) > 127 {
			return "", 0, errors.New("DNS name too long")
		}
	}
	if i+4 > len(msg) {
		return "", 0, errors.New("truncated DNS question type/class")
	}
	return strings.Join(labels, "."), i + 4, nil
}

func dnsErrorResponse(query []byte, rcode uint16) []byte {
	_, end, err := dnsQuestionName(query)
	if err != nil {
		return nil
	}
	out := append([]byte(nil), query[:end]...)
	flags := binary.BigEndian.Uint16(out[2:4])
	flags |= 0x8000 | 0x0080
	flags = (flags & 0xfff0) | (rcode & 0x000f)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

func dnsTruncatedResponse(msg []byte) []byte {
	out := append([]byte(nil), msg...)
	if len(out) >= 12 {
		flags := binary.BigEndian.Uint16(out[2:4]) | 0x8200
		binary.BigEndian.PutUint16(out[2:4], flags)
		binary.BigEndian.PutUint16(out[6:8], 0)
		binary.BigEndian.PutUint16(out[8:10], 0)
		binary.BigEndian.PutUint16(out[10:12], 0)
		if _, end, err := dnsQuestionName(out); err == nil {
			out = out[:end]
		}
	}
	return out
}

func (f *dnsAdFilter) handleQuery(query []byte, network string) ([]byte, error) {
	domain, _, err := dnsQuestionName(query)
	if err != nil {
		return nil, err
	}
	if f.isBlocked(domain) {
		return dnsErrorResponse(query, 3), nil
	} // NXDOMAIN
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, network, f.upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if network == "tcp" {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		if _, err = conn.Write(size[:]); err != nil {
			return nil, err
		}
		if _, err = conn.Write(query); err != nil {
			return nil, err
		}
		if _, err = io.ReadFull(conn, size[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 || n > 4096 {
			return nil, errors.New("invalid upstream DNS response size")
		}
		resp := make([]byte, n)
		_, err = io.ReadFull(conn, resp)
		return resp, err
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

func (f *dnsAdFilter) refreshLoop() {
	// Start immediately in the background so the tunnel doesn't wait for this download.
	for {
		f.refreshBlocklist()
		time.Sleep(12 * time.Hour)
	}
}

func (f *dnsAdFilter) refreshBlocklist() {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", nil)
	if err != nil {
		return
	}
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		log.Printf("DNS ad list update unavailable; using built-in domains")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("DNS ad list update unavailable (HTTP %d); using cached domains", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil || len(body) == 16<<20 {
		log.Printf("DNS ad list update rejected; using cached domains")
		return
	}
	newSet := make(map[string]struct{}, len(f.blocked)+100000)
	f.mu.RLock()
	for d := range f.blocked {
		if isBuiltinDomain(d) {
			newSet[d] = struct{}{}
		}
	}
	f.mu.RUnlock()
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		fields := strings.Fields(line)
		if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
			continue
		}
		for _, d := range fields[1:] {
			d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
			if d == "" || strings.ContainsAny(d, "/:* ") || d == "localhost" || strings.HasSuffix(d, ".localhost") || !strings.Contains(d, ".") {
				continue
			}
			newSet[d] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("DNS ad list parser failed; keeping cached domains")
		return
	}
	f.mu.Lock()
	f.blocked = newSet
	f.mu.Unlock()
	log.Printf("DNS ad/tracker blocklist updated (%d domains)", len(newSet))
}

func isBuiltinDomain(domain string) bool {
	for _, d := range builtinAdDomains {
		if domain == d {
			return true
		}
	}
	return false
}
