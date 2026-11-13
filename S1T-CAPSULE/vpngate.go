package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const vpnGateAPIURL = "https://www.vpngate.net/api/iphone/"

// VPN Gate is a public relay network run by volunteers. The API publishes a
// ready-to-use OpenVPN profile as base64 in each CSV row. The client only
// accepts TCP profiles because ShahTunnel's managed OpenVPN egress is TCP-only.
type vpnGateServer struct {
	HostName    string
	IP          string
	Country     string
	CountryCode string
	PingMS      int64
	SpeedBPS    int64
	Sessions    int64
	Score       int64
	Port        int
	Config      []byte
}

func parseVPNGateCSV(body []byte) ([]vpnGateServer, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	first, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read VPN Gate API marker: %w", err)
	}
	if len(first) == 0 || !strings.HasPrefix(strings.TrimSpace(first[0]), "*vpn_servers") {
		return nil, errors.New("VPN Gate API response has an unexpected header")
	}
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read VPN Gate CSV header: %w", err)
	}
	indices := make(map[string]int, len(header))
	for i, h := range header {
		name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(h), "#"))
		indices[strings.ToLower(name)] = i
	}
	for _, required := range []string{"hostname", "ip", "ping", "speed", "countrylong", "countryshort", "numvpnsessions", "score", "openvpn_configdata_base64"} {
		if _, ok := indices[required]; !ok {
			return nil, fmt.Errorf("VPN Gate API is missing required CSV field %q", required)
		}
	}
	get := func(row []string, name string) string {
		i, ok := indices[name]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	parseInt := func(s string) int64 {
		n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return n
	}
	var servers []vpnGateServer
	for {
		row, readErr := r.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("parse VPN Gate CSV row: %w", readErr)
		}
		if len(row) == 0 || strings.HasPrefix(strings.TrimSpace(row[0]), "*") {
			continue
		}
		ip := net.ParseIP(get(row, "ip"))
		if ip == nil || ip.To4() == nil {
			continue
		}
		encoded := get(row, "openvpn_configdata_base64")
		if encoded == "" {
			continue
		}
		conf, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			conf, decodeErr = base64.RawStdEncoding.DecodeString(encoded)
		}
		if decodeErr != nil || len(conf) == 0 || len(conf) > 2*1024*1024 {
			continue
		}
		normalized, port, ok := normalizeVPNGateTCPProfile(string(conf), ip.String())
		if !ok {
			continue
		}
		country := get(row, "countrylong")
		code := strings.ToUpper(get(row, "countryshort"))
		if country == "" || code == "" {
			continue
		}
		servers = append(servers, vpnGateServer{
			HostName: get(row, "hostname"), IP: ip.String(), Country: country, CountryCode: code,
			PingMS: parseInt(get(row, "ping")), SpeedBPS: parseInt(get(row, "speed")),
			Sessions: parseInt(get(row, "numvpnsessions")), Score: parseInt(get(row, "score")),
			Port: port, Config: []byte(normalized),
		})
	}
	if len(servers) == 0 {
		return nil, errors.New("VPN Gate returned no usable OpenVPN TCP profiles; its current list may contain only UDP profiles")
	}
	return servers, nil
}

// normalizeVPNGateTCPProfile validates that the API's decoded profile is TCP,
// pins its remote to the IP supplied in the same signed-HTTPS API response, and
// forces VPN Gate's published public credentials (vpn/vpn) without executing
// any provider-supplied scripts or changing host routes.
func normalizeVPNGateTCPProfile(raw, apiIP string) (string, int, bool) {
	if net.ParseIP(apiIP) == nil {
		return "", 0, false
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	protoTCP, remoteSeen, authSeen := false, false, false
	port := 0
	out := make([]string, 0, len(lines)+2)
	for _, line := range lines {
		key, args := openVPNDirective(line)
		if key == "proto" {
			if len(args) == 0 || !(strings.EqualFold(args[0], "tcp") || strings.EqualFold(args[0], "tcp-client")) {
				return "", 0, false
			}
			protoTCP = true
			out = append(out, "proto tcp-client")
			continue
		}
		if key == "remote" {
			// A relay row describes one endpoint. Ignore any secondary remotes
			// in the embedded profile so the TCP probe and final client use
			// exactly the same API-pinned IP and port.
			if remoteSeen {
				continue
			}
			if len(args) < 2 {
				return "", 0, false
			}
			p, err := strconv.Atoi(args[1])
			if err != nil || p < 1 || p > 65535 {
				return "", 0, false
			}
			if len(args) >= 3 && strings.EqualFold(args[2], "udp") {
				return "", 0, false
			}
			// If an explicit per-remote transport is present, it must be TCP.
			if len(args) >= 3 && !strings.EqualFold(args[2], "tcp") && !strings.EqualFold(args[2], "tcp-client") {
				return "", 0, false
			}
			port = p
			remoteSeen = true
			out = append(out, "remote "+apiIP+" "+strconv.Itoa(p))
			continue
		}
		if key == "auth-user-pass" {
			authSeen = true
			out = append(out, "auth-user-pass")
			continue
		}
		out = append(out, line)
	}
	if !protoTCP || !remoteSeen || port == 0 {
		return "", 0, false
	}
	if !authSeen {
		out = append(out, "auth-user-pass")
	}
	return strings.Join(out, "\n") + "\n", port, true
}

func fetchVPNGateServers(ctx context.Context) ([]vpnGateServer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vpnGateAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ShahTunnel/4.0.0 VPNGate-Free-Egress")
	req.Header.Set("Accept", "text/csv,*/*;q=0.8")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch official VPN Gate server list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("official VPN Gate API returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024+1))
	if err != nil {
		return nil, fmt.Errorf("read VPN Gate server list: %w", err)
	}
	if len(body) > 32*1024*1024 {
		return nil, errors.New("VPN Gate server list is unexpectedly large")
	}
	servers, err := parseVPNGateCSV(body)
	if err != nil {
		return nil, err
	}
	return servers, nil
}

func rankVPNGateServers(servers []vpnGateServer) {
	sort.SliceStable(servers, func(i, j int) bool {
		a, b := servers[i], servers[j]
		if (a.PingMS > 0) != (b.PingMS > 0) {
			return a.PingMS > 0
		}
		if a.PingMS > 0 && b.PingMS > 0 && a.PingMS != b.PingMS {
			return a.PingMS < b.PingMS
		}
		if a.SpeedBPS != b.SpeedBPS {
			return a.SpeedBPS > b.SpeedBPS
		}
		if a.Sessions != b.Sessions {
			return a.Sessions < b.Sessions
		}
		return a.Score > b.Score
	})
}

func chooseVPNGateCountry(servers []vpnGateServer) (string, error) {
	type countryCount struct {
		Code  string
		Name  string
		Count int
	}
	counts := map[string]*countryCount{}
	for _, server := range servers {
		item := counts[server.CountryCode]
		if item == nil {
			item = &countryCount{Code: server.CountryCode, Name: server.Country}
			counts[server.CountryCode] = item
		}
		item.Count++
	}
	countries := make([]countryCount, 0, len(counts))
	for _, item := range counts {
		countries = append(countries, *item)
	}
	sort.Slice(countries, func(i, j int) bool {
		if countries[i].Count != countries[j].Count {
			return countries[i].Count > countries[j].Count
		}
		return countries[i].Name < countries[j].Name
	})
	fmt.Printf("\n  %s\n", paint(ansiCyan+ansiBold, "FREE VPN GATE — SELECT EXIT COUNTRY"))
	fmt.Println("  0) Automatic — best reachable server from all countries")
	for i, country := range countries {
		fmt.Printf("  %2d) %-28s %s (%d TCP servers)\n", i+1, country.Name, country.Code, country.Count)
	}
	answer := strings.TrimSpace(wizardAsk("Select country number (0 = Automatic)", "0"))
	if answer == "" || answer == "0" {
		return "", nil
	}
	index, err := strconv.Atoi(answer)
	if err != nil || index < 1 || index > len(countries) {
		return "", errors.New("invalid VPN Gate country selection")
	}
	return countries[index-1].Code, nil
}

func probeVPNGateServers(servers []vpnGateServer, maxCandidates int) []vpnGateServer {
	if maxCandidates <= 0 {
		return nil
	}
	rankVPNGateServers(servers)
	if len(servers) > 40 {
		servers = servers[:40]
	}
	type result struct {
		server vpnGateServer
		ok     bool
	}
	results := make(chan result, len(servers))
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, candidate := range servers {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			address := net.JoinHostPort(candidate.IP, strconv.Itoa(candidate.Port))
			conn, err := net.DialTimeout("tcp", address, 1800*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				results <- result{server: candidate, ok: true}
				return
			}
			results <- result{server: candidate, ok: false}
		}()
	}
	wg.Wait()
	close(results)
	var reachable []vpnGateServer
	for item := range results {
		if item.ok {
			reachable = append(reachable, item.server)
		}
	}
	rankVPNGateServers(reachable)
	if len(reachable) > maxCandidates {
		reachable = reachable[:maxCandidates]
	}
	return reachable
}

func vpnGateServerLabel(server vpnGateServer) string {
	host := server.HostName
	if host == "" {
		host = server.IP
	}
	return fmt.Sprintf("%s (%s, %s / %s:%d, API ping %d ms)", server.Country, server.CountryCode, host, server.IP, server.Port, server.PingMS)
}
