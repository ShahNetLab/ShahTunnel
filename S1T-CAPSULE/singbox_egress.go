package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	underlayTUIC    = "tuic"
	underlayReality = "vless_reality"
	egressTUIC      = "tuic"
	egressReality   = "vless_reality"
	singBoxVersion  = "1.14.4"
)

type ProtocolEgress struct {
	Protocol          string            `json:"protocol"`
	Server            string            `json:"server"`
	ServerPort        int               `json:"server_port"`
	UUID              string            `json:"uuid"`
	Password          string            `json:"password,omitempty"`
	ServerName        string            `json:"server_name"`
	PublicKey         string            `json:"public_key,omitempty"`
	ShortID           string            `json:"short_id,omitempty"`
	Fingerprint       string            `json:"fingerprint,omitempty"`
	CongestionControl string            `json:"congestion_control,omitempty"`
	Proxy             string            `json:"proxy"`
	SingBoxConfigPath string            `json:"sing_box_config_path,omitempty"`
	SingBoxService    string            `json:"sing_box_service,omitempty"`
	XrayConfigPath    string            `json:"xray_config_path,omitempty"`
	XrayService       string            `json:"xray_service,omitempty"`
	XrayOutboundTag   string            `json:"xray_outbound_tag,omitempty"`
	VerifiedExitIP    string            `json:"verified_exit_ip,omitempty"`
	Bindings          []XrayWarpBinding `json:"bindings,omitempty"`
}

var protocolUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

func validProtocolEgress(c Config) error {
	if c.Role != "agent" {
		return errors.New("TUIC and VLESS REALITY egress can only be configured on an Agent")
	}
	p := c.ProtocolEgress
	if p == nil {
		return errors.New("protocol_egress settings are missing")
	}
	if p.Protocol != egressTUIC && p.Protocol != egressReality {
		return fmt.Errorf("unsupported protocol egress %q", p.Protocol)
	}
	if (c.Underlay == underlayTUIC && p.Protocol != egressTUIC) || (c.Underlay == underlayReality && p.Protocol != egressReality) {
		return errors.New("selected Agent underlay does not match protocol_egress.protocol")
	}
	if strings.TrimSpace(p.Server) == "" || strings.ContainsAny(p.Server, "\r\n\x00 /\\") {
		return errors.New("egress server must be a hostname or IP address without URL/path syntax")
	}
	if net.ParseIP(p.Server) == nil && !validTLSServerName(p.Server) {
		return errors.New("egress server must be a valid hostname or IP address")
	}
	if p.ServerPort < 1 || p.ServerPort > 65535 {
		return errors.New("egress server_port must be between 1 and 65535")
	}
	if !protocolUUIDPattern.MatchString(p.UUID) {
		return errors.New("egress UUID is invalid")
	}
	if !validTLSServerName(p.ServerName) {
		return errors.New("egress server_name must be a DNS hostname")
	}
	if p.Protocol == egressTUIC {
		if strings.TrimSpace(p.Password) == "" || len(p.Password) > 256 || strings.ContainsAny(p.Password, "\r\n\x00") {
			return errors.New("TUIC password must be 1–256 characters and contain no line breaks")
		}
		if p.CongestionControl == "" {
			p.CongestionControl = "bbr"
		}
		if p.CongestionControl != "bbr" && p.CongestionControl != "cubic" && p.CongestionControl != "new_reno" {
			return errors.New("TUIC congestion_control must be bbr, cubic, or new_reno")
		}
	} else {
		key, err := decodeRealityKey(p.PublicKey)
		if err != nil || len(key) != 32 {
			return errors.New("VLESS REALITY public_key must be a 32-byte base64url X25519 public key")
		}
		if len(p.ShortID) > 16 || len(p.ShortID)%2 != 0 {
			return errors.New("REALITY short_id must contain 0–16 hexadecimal characters in pairs")
		}
		if _, err := hex.DecodeString(p.ShortID); err != nil {
			return errors.New("REALITY short_id must be hexadecimal")
		}
		if p.Fingerprint == "" {
			p.Fingerprint = "chrome"
		}
		switch p.Fingerprint {
		case "chrome", "firefox", "safari", "edge", "random", "randomized":
		default:
			return errors.New("REALITY fingerprint must be chrome, firefox, safari, edge, random, or randomized")
		}
	}
	if p.Proxy != "" && !isLoopbackProxyAddress(p.Proxy) {
		return errors.New("protocol egress SOCKS5 listener must be loopback-only")
	}
	return nil
}

func decodeRealityKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func allocateLoopbackSOCKSPort() (string, error) {
	for i := 0; i < 32; i++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return "", err
		}
		port := tcp.Addr().(*net.TCPAddr).Port
		udp, udpErr := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		_ = tcp.Close()
		if udpErr == nil {
			_ = udp.Close()
			return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
		}
	}
	return "", errors.New("could not allocate a free loopback TCP/UDP SOCKS5 port")
}

func buildSingBoxEgressConfig(p ProtocolEgress) ([]byte, error) {
	if p.Proxy == "" {
		return nil, errors.New("sing-box loopback SOCKS5 address is missing")
	}
	host, portText, err := net.SplitHostPort(p.Proxy)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("sing-box SOCKS5 listener must use a loopback IP:PORT")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("sing-box SOCKS5 listener port is invalid")
	}
	if p.Protocol != egressTUIC && p.Protocol != egressReality {
		return nil, fmt.Errorf("unsupported sing-box egress protocol %q", p.Protocol)
	}
	outbound := map[string]any{"tag": "s1t-egress", "server": p.Server, "server_port": p.ServerPort}
	if p.Protocol == egressTUIC {
		cc := p.CongestionControl
		if cc == "" {
			cc = "bbr"
		}
		outbound["type"] = "tuic"
		outbound["uuid"] = p.UUID
		outbound["password"] = p.Password
		outbound["congestion_control"] = cc
		outbound["udp_relay_mode"] = "native"
		outbound["zero_rtt_handshake"] = false
		outbound["heartbeat"] = "10s"
		outbound["tls"] = map[string]any{"enabled": true, "server_name": p.ServerName, "alpn": []any{"h3"}, "insecure": false}
	} else {
		fp := p.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		outbound["type"] = "vless"
		outbound["uuid"] = p.UUID
		outbound["flow"] = "xtls-rprx-vision"
		outbound["packet_encoding"] = "xudp"
		outbound["tls"] = map[string]any{
			"enabled":     true,
			"server_name": p.ServerName,
			"utls":        map[string]any{"enabled": true, "fingerprint": fp},
			"reality":     map[string]any{"enabled": true, "public_key": p.PublicKey, "short_id": p.ShortID},
		}
	}
	root := map[string]any{
		"log":       map[string]any{"level": "warn", "timestamp": true},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "s1t-local-socks", "listen": "127.0.0.1", "listen_port": port}},
		"outbounds": []any{outbound},
		"route":     map[string]any{"final": "s1t-egress", "auto_detect_interface": true},
	}
	b, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func singBoxServiceName(profileID, protocol string) string {
	return "shah-tunnel-singbox-" + safeXrayTag(protocol) + "-" + tunnelID(profileID) + ".service"
}

func singBoxDirectory(profileID, protocol string) string {
	return filepath.Join("/etc/ravanreverse/sing-box", safeXrayTag(protocol), tunnelID(profileID))
}

func singBoxUnitPath(service string) (string, error) {
	if filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-singbox-") || !strings.HasSuffix(service, ".service") {
		return "", fmt.Errorf("refusing to manage non-ShahTunnel sing-box unit %q", service)
	}
	return filepath.Join("/etc/systemd/system", service), nil
}

func singBoxBinary() (string, error) {
	for _, candidate := range []string{"/usr/local/bin/sing-box", "/usr/bin/sing-box"} {
		if info, err := os.Stat(candidate); err != nil || info.IsDir() || info.Mode()&0111 == 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, versionErr := exec.CommandContext(ctx, candidate, "version").CombinedOutput()
		cancel()
		if versionErr == nil && strings.Contains(string(out), "sing-box version "+singBoxVersion) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("the pinned sing-box %s runtime is not installed; run the verified ShahTunnel installer", singBoxVersion)
}

func ensureSingBoxInstalled() error {
	if _, err := singBoxBinary(); err == nil {
		return nil
	}
	candidates := []string{"/var/lib/shah-tunnel/install-sing-box.sh"}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "scripts", "install-sing-box.sh"))
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		cmd := exec.Command("bash", path)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("install verified sing-box runtime: %w", err)
		}
		if _, err := singBoxBinary(); err == nil {
			return nil
		}
	}
	return errors.New("sing-box runtime is missing and the verified installer helper was not found")
}

func validateSingBoxConfig(configPath string) error {
	binary, err := singBoxBinary()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "check", "-c", configPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sing-box rejected the generated config: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func renderSingBoxUnit(binary, configPath, service string) ([]byte, error) {
	if binary == "" || configPath == "" || filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-singbox-") {
		return nil, errors.New("invalid ShahTunnel sing-box service parameters")
	}
	for _, value := range []string{binary, configPath} {
		if strings.ContainsAny(value, "\x00\n\r") {
			return nil, errors.New("sing-box service paths contain control characters")
		}
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel isolated protocol egress (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s run -c %s
Restart=always
RestartSec=2
LimitNOFILE=262144
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=%s
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target
`, strings.TrimSuffix(service, ".service"), systemdExecQuote(binary), systemdExecQuote(configPath), systemdExecQuote(filepath.Dir(configPath)))
	return []byte(unit), nil
}

func singBoxJournal(service string) string {
	out, _ := exec.Command("journalctl", "-u", service, "-n", "35", "--no-pager", "-o", "cat").CombinedOutput()
	return strings.TrimSpace(string(out))
}

func waitForSingBoxProxy(service, proxy string) error {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", proxy, 400*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		if exec.Command("systemctl", "is-active", "--quiet", service).Run() != nil {
			return fmt.Errorf("sing-box service %s is not active; journal: %s", service, singBoxJournal(service))
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("sing-box service %s did not open loopback SOCKS5 %s; journal: %s", service, proxy, singBoxJournal(service))
}

func installSingBoxSidecar(p *ProtocolEgress, profileID string) error {
	if p == nil {
		return errors.New("protocol egress config is nil")
	}
	if err := ensureSingBoxInstalled(); err != nil {
		return err
	}
	binary, err := singBoxBinary()
	if err != nil {
		return err
	}
	if p.Proxy == "" {
		p.Proxy, err = allocateLoopbackSOCKSPort()
		if err != nil {
			return err
		}
	}
	configData, err := buildSingBoxEgressConfig(*p)
	if err != nil {
		return err
	}
	service := singBoxServiceName(profileID, p.Protocol)
	unitPath, err := singBoxUnitPath(service)
	if err != nil {
		return err
	}
	dir := singBoxDirectory(profileID, p.Protocol)
	configPath := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	if err := atomicReplaceFile(configPath, configData, 0600); err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	if err := validateSingBoxConfig(configPath); err != nil {
		_ = os.Remove(configPath)
		_ = os.Remove(dir)
		return err
	}
	unit, err := renderSingBoxUnit(binary, configPath, service)
	if err != nil {
		_ = os.Remove(configPath)
		_ = os.Remove(dir)
		return err
	}
	if err := atomicReplaceFile(unitPath, unit, 0644); err != nil {
		_ = os.Remove(configPath)
		_ = os.Remove(dir)
		return err
	}
	if err := systemdReload(); err != nil {
		_ = os.Remove(unitPath)
		_ = os.RemoveAll(dir)
		return err
	}
	out, err := exec.Command("systemctl", "enable", "--now", service).CombinedOutput()
	if err != nil {
		journal := singBoxJournal(service)
		_ = exec.Command("systemctl", "disable", "--now", service).Run()
		_ = os.Remove(unitPath)
		_ = os.RemoveAll(dir)
		_ = systemdReload()
		return fmt.Errorf("start sing-box service %s: %w: %s; journal: %s", service, err, strings.TrimSpace(string(out)), journal)
	}
	if err := waitForSingBoxProxy(service, p.Proxy); err != nil {
		_ = exec.Command("systemctl", "disable", "--now", service).Run()
		_ = os.Remove(unitPath)
		_ = os.RemoveAll(dir)
		_ = systemdReload()
		return err
	}
	p.SingBoxConfigPath, p.SingBoxService = configPath, service
	return nil
}

func ensureSingBoxSidecar(p *ProtocolEgress) error {
	if p == nil || p.SingBoxService == "" || p.SingBoxConfigPath == "" || !isLoopbackProxyAddress(p.Proxy) {
		return errors.New("protocol egress sidecar metadata is incomplete")
	}
	unitPath, err := singBoxUnitPath(p.SingBoxService)
	if err != nil {
		return err
	}
	if _, err := os.Stat(unitPath); err != nil {
		return fmt.Errorf("sing-box unit is missing: %w", err)
	}
	if _, err := os.Stat(p.SingBoxConfigPath); err != nil {
		return fmt.Errorf("sing-box config is missing: %w", err)
	}
	if err := exec.Command("systemctl", "start", p.SingBoxService).Run(); err != nil {
		return fmt.Errorf("start sing-box egress: %w: %s", err, singBoxJournal(p.SingBoxService))
	}
	return waitForSingBoxProxy(p.SingBoxService, p.Proxy)
}

func removeSingBoxSidecar(p *ProtocolEgress) error {
	if p == nil || p.SingBoxService == "" {
		return nil
	}
	unitPath, err := singBoxUnitPath(p.SingBoxService)
	if err != nil {
		return err
	}
	dir := singBoxDirectoryFromConfig(p.SingBoxConfigPath)
	if dir == "" {
		return errors.New("refusing to remove sing-box config outside ShahTunnel protocol directory")
	}
	out, stopErr := exec.Command("systemctl", "disable", "--now", p.SingBoxService).CombinedOutput()
	if stopErr != nil {
		state, _ := exec.Command("systemctl", "show", p.SingBoxService, "-p", "LoadState", "--value").Output()
		if strings.TrimSpace(string(state)) != "not-found" {
			return fmt.Errorf("stop sing-box service: %w: %s", stopErr, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := systemdReload(); err != nil {
		return err
	}
	return nil
}

func singBoxDirectoryFromConfig(configPath string) string {
	clean := filepath.Clean(configPath)
	root := filepath.Clean("/etc/ravanreverse/sing-box") + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" {
		return ""
	}
	return filepath.Dir(clean)
}

func xrayProtocolServiceName(profileID, protocol string) string {
	return "shah-tunnel-xray-" + safeXrayTag(protocol) + "-" + tunnelID(profileID) + ".service"
}

func xrayProtocolDirectory(profileID, protocol string) string {
	return filepath.Join("/etc/ravanreverse/xray-protocol", safeXrayTag(protocol), tunnelID(profileID))
}

func renderXrayProtocolUnit(runtime xrayRuntime, configPath, service, singBoxService string) ([]byte, error) {
	if runtime.Binary == "" || runtime.CWD == "" || configPath == "" || filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-") {
		return nil, errors.New("invalid isolated Xray protocol service parameters")
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel isolated Xray protocol egress (%s)
After=network-online.target %s
Wants=network-online.target %s

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s run -config %s
Restart=on-failure
RestartSec=2
LimitNOFILE=262144
KillSignal=SIGINT
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=%s
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
`, strings.TrimSuffix(service, ".service"), singBoxService, singBoxService, runtime.CWD, systemdExecQuote(runtime.Binary), systemdExecQuote(configPath), systemdExecQuote(filepath.Dir(configPath)))
	return []byte(unit), nil
}

func installXrayProtocolSidecar(runtime xrayRuntime, profileID, protocol string, generated []byte, bindings []XrayWarpBinding, singBoxService string) (string, string, error) {
	service := xrayProtocolServiceName(profileID, protocol)
	unitPath := filepath.Join("/etc/systemd/system", service)
	dir := xrayProtocolDirectory(profileID, protocol)
	configPath := filepath.Join(dir, "config.json")
	if _, err := os.Stat(unitPath); err == nil {
		return "", "", fmt.Errorf("managed Xray protocol unit %s already exists", service)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", err
	}
	cleanup := func() {
		_ = exec.Command("systemctl", "disable", "--now", service).Run()
		_ = os.Remove(unitPath)
		_ = os.RemoveAll(dir)
		_ = systemdReload()
	}
	if err := atomicReplaceFile(configPath, generated, 0600); err != nil {
		cleanup()
		return "", "", err
	}
	unit, err := renderXrayProtocolUnit(runtime, configPath, service, singBoxService)
	if err != nil {
		cleanup()
		return "", "", err
	}
	if err := atomicReplaceFile(unitPath, unit, 0644); err != nil {
		cleanup()
		return "", "", err
	}
	if err := systemdReload(); err != nil {
		cleanup()
		return "", "", err
	}
	out, err := exec.Command("systemctl", "enable", "--now", service).CombinedOutput()
	if err != nil {
		journal := xrayWarpJournal(service)
		cleanup()
		return "", "", fmt.Errorf("start isolated Xray service %s: %w: %s; journal: %s", service, err, strings.TrimSpace(string(out)), journal)
	}
	if err := waitForXrayWarpInbounds(service, bindings); err != nil {
		journal := xrayWarpJournal(service)
		cleanup()
		return "", "", fmt.Errorf("%w; journal: %s", err, journal)
	}
	return configPath, service, nil
}

func removeXrayProtocolSidecar(p *ProtocolEgress) error {
	if p == nil || p.XrayService == "" {
		return nil
	}
	if filepath.Base(p.XrayService) != p.XrayService || !strings.HasPrefix(p.XrayService, "shah-tunnel-xray-") || !strings.HasSuffix(p.XrayService, ".service") {
		return errors.New("refusing to stop an unmanaged Xray protocol service")
	}
	clean := filepath.Clean(p.XrayConfigPath)
	root := filepath.Clean("/etc/ravanreverse/xray-protocol") + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" {
		return errors.New("refusing to remove Xray protocol config outside ShahTunnel directory")
	}
	out, err := exec.Command("systemctl", "disable", "--now", p.XrayService).CombinedOutput()
	if err != nil {
		state, _ := exec.Command("systemctl", "show", p.XrayService, "-p", "LoadState", "--value").Output()
		if strings.TrimSpace(string(state)) != "not-found" {
			return fmt.Errorf("stop isolated Xray protocol service: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Remove(filepath.Join("/etc/systemd/system", p.XrayService)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(filepath.Dir(clean)); err != nil {
		return err
	}
	return systemdReload()
}

func probeSOCKS5PublicIP(proxy string) (string, error) {
	tr := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialSOCKS5Context(ctx, proxy, address)
	}, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 8 * time.Second, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 14 * time.Second}
	for _, endpoint := range []string{"https://api.ipify.org", "https://icanhazip.com"} {
		resp, err := client.Get(endpoint)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		ipText := strings.TrimSpace(string(body))
		if net.ParseIP(ipText) != nil {
			return ipText, nil
		}
	}
	return "", errors.New("could not verify the public IP through the selected protocol egress")
}

func directPublicIP() string {
	client := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 5 * time.Second}}
	for _, endpoint := range []string{"https://api.ipify.org", "https://icanhazip.com"} {
		resp, err := client.Get(endpoint)
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		if readErr == nil && resp.StatusCode == http.StatusOK && net.ParseIP(strings.TrimSpace(string(body))) != nil {
			return strings.TrimSpace(string(body))
		}
	}
	return ""
}

func validateDistinctExitIP(exitIP, directIP string) error {
	exit := net.ParseIP(strings.TrimSpace(exitIP))
	direct := net.ParseIP(strings.TrimSpace(directIP))
	if exit == nil {
		return errors.New("selected protocol egress did not return a valid public IP")
	}
	if direct == nil {
		return errors.New("could not independently detect the Agent direct public IP; refusing to claim or enable a different exit IP")
	}
	if exit.Equal(direct) {
		return fmt.Errorf("selected protocol server returned the Agent's direct IP %s; refusing to expose this profile on an unchanged egress", exit.String())
	}
	return nil
}

func applyProtocolEgressForAgent(cfg *Config) error {
	if cfg == nil || (cfg.Underlay != underlayTUIC && cfg.Underlay != underlayReality) {
		return nil
	}
	if err := validProtocolEgress(*cfg); err != nil {
		return err
	}
	if cfg.XrayWARP != nil || cfg.XrayPsiphon != nil || cfg.XrayTor != nil || cfg.ProtocolEgress.XrayService != "" {
		return errors.New("this Agent profile already has an isolated Xray egress; remove it before changing protocol")
	}
	p := cfg.ProtocolEgress
	profileID := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if err := installSingBoxSidecar(p, profileID); err != nil {
		return fmt.Errorf("prepare %s egress: %w", p.Protocol, err)
	}
	rollbackSingBox := func() { _ = removeSingBoxSidecar(p) }
	// Authenticate the real remote exit before any public mapping is switched.
	exitIP, err := probeSOCKS5PublicIP(p.Proxy)
	if err != nil {
		rollbackSingBox()
		return err
	}
	directIP := directPublicIP()
	if directIP == "" {
		rollbackSingBox()
		return errors.New("could not independently detect the Agent direct public IP; refusing to claim or enable a different exit IP")
	}
	if err := validateDistinctExitIP(exitIP, directIP); err != nil {
		rollbackSingBox()
		return err
	}
	var runtime xrayRuntime
	for i, mapping := range cfg.Ports {
		_, portText, splitErr := net.SplitHostPort(mapping.Target)
		if splitErr != nil {
			rollbackSingBox()
			return fmt.Errorf("mapping %q target must be IP:PORT: %w", mapping.ID, splitErr)
		}
		port, convErr := strconv.Atoi(portText)
		if convErr != nil || port < 1 || port > 65535 {
			rollbackSingBox()
			return fmt.Errorf("mapping %q target port is invalid", mapping.ID)
		}
		rt, _, findErr := findXrayRuntimeForPort(port)
		if findErr != nil {
			rollbackSingBox()
			return fmt.Errorf("detect Xray for mapping %q: %w", mapping.ID, findErr)
		}
		if i == 0 {
			runtime = rt
		} else if filepath.Clean(runtime.ConfigPath) != filepath.Clean(rt.ConfigPath) || runtime.Binary != rt.Binary || runtime.CWD != rt.CWD {
			rollbackSingBox()
			return errors.New("all protocol-egress mappings in one tunnel must belong to the same Xray instance")
		}
	}
	originalXray, err := os.ReadFile(runtime.ConfigPath)
	if err != nil {
		rollbackSingBox()
		return fmt.Errorf("read Xray source config: %w", err)
	}
	generated, bindings, outTag, err := buildXrayEgressConfig(originalXray, profileID, p.Proxy, cfg.Ports, p.Protocol, false)
	if err != nil {
		rollbackSingBox()
		return err
	}
	stateDir := xrayProtocolDirectory(profileID, p.Protocol)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		rollbackSingBox()
		return err
	}
	testFile, err := os.CreateTemp(stateDir, ".config-test-*.json")
	if err != nil {
		rollbackSingBox()
		return err
	}
	testPath := testFile.Name()
	if _, err = testFile.Write(generated); err == nil {
		err = testFile.Chmod(0600)
	}
	if closeErr := testFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(testPath)
		rollbackSingBox()
		return err
	}
	defer os.Remove(testPath)
	if err := validateXrayConfig(runtime, testPath); err != nil {
		rollbackSingBox()
		return err
	}
	xrayConfig, xrayService, err := installXrayProtocolSidecar(runtime, profileID, p.Protocol, generated, bindings, p.SingBoxService)
	if err != nil {
		rollbackSingBox()
		return err
	}
	byID := make(map[string]XrayWarpBinding, len(bindings))
	for _, binding := range bindings {
		byID[binding.MappingID] = binding
	}
	originalTargets := make([]string, len(cfg.Ports))
	for i := range cfg.Ports {
		originalTargets[i] = cfg.Ports[i].Target
		binding, ok := byID[cfg.Ports[i].ID]
		if !ok {
			_ = removeXrayProtocolSidecar(&ProtocolEgress{XrayConfigPath: xrayConfig, XrayService: xrayService})
			rollbackSingBox()
			return fmt.Errorf("no isolated Xray binding for mapping %q", cfg.Ports[i].ID)
		}
		cfg.Ports[i].Target = binding.WarpTarget
	}
	p.XrayConfigPath, p.XrayService, p.XrayOutboundTag, p.VerifiedExitIP, p.Bindings = xrayConfig, xrayService, outTag, exitIP, bindings
	if err := saveConfig(*cfg); err != nil {
		for i := range cfg.Ports {
			cfg.Ports[i].Target = originalTargets[i]
		}
		_ = removeXrayProtocolSidecar(p)
		rollbackSingBox()
		return fmt.Errorf("save protocol egress profile: %w", err)
	}
	uiSuccess(fmt.Sprintf("%s egress verified; remote public IP: %s", p.Protocol, exitIP))
	uiInfo("Only this Agent profile's selected Xray inbounds were cloned into an isolated sidecar.")
	uiInfo("UDP is forwarded through the selected proxy protocol; no direct fallback or host-wide route change was added.")
	return nil
}

func ensureProtocolEgressServices(cfg Config) error {
	p := cfg.ProtocolEgress
	if p == nil {
		return errors.New("selected protocol egress configuration is missing")
	}
	if err := ensureSingBoxSidecar(p); err != nil {
		return err
	}
	exitIP, err := probeSOCKS5PublicIP(p.Proxy)
	if err != nil {
		return fmt.Errorf("cannot verify the selected protocol egress on Agent start: %w", err)
	}
	directIP := directPublicIP()
	if err := validateDistinctExitIP(exitIP, directIP); err != nil {
		return err
	}
	if p.VerifiedExitIP != exitIP {
		oldIP := p.VerifiedExitIP
		p.VerifiedExitIP = exitIP
		if err := saveConfig(cfg); err != nil {
			p.VerifiedExitIP = oldIP
			return fmt.Errorf("verified exit IP changed to %s but could not persist the updated value: %w", exitIP, err)
		}
		uiInfo(fmt.Sprintf("Verified protocol egress IP updated: %s", exitIP))
	}
	if p.XrayService != "" {
		clean := filepath.Clean(p.XrayConfigPath)
		root := filepath.Clean("/etc/ravanreverse/xray-protocol") + string(os.PathSeparator)
		if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" || filepath.Base(p.XrayService) != p.XrayService || !strings.HasPrefix(p.XrayService, "shah-tunnel-xray-") {
			return errors.New("isolated Xray protocol service metadata is invalid")
		}
		if err := exec.Command("systemctl", "start", p.XrayService).Run(); err != nil {
			return fmt.Errorf("start isolated Xray protocol service: %w: %s", err, xrayWarpJournal(p.XrayService))
		}
		for _, b := range p.Bindings {
			conn, err := net.DialTimeout("tcp", b.WarpTarget, 700*time.Millisecond)
			if err != nil {
				return fmt.Errorf("isolated Xray inbound for mapping %s is not ready: %w", b.MappingID, err)
			}
			_ = conn.Close()
		}
	}
	return nil
}

func removeProtocolEgressIntegration(cfg *Config) error {
	if cfg == nil || cfg.ProtocolEgress == nil {
		return nil
	}
	p := cfg.ProtocolEgress
	if err := removeXrayProtocolSidecar(p); err != nil {
		return err
	}
	for i := range cfg.Ports {
		for _, binding := range p.Bindings {
			if cfg.Ports[i].ID == binding.MappingID {
				cfg.Ports[i].Target = binding.OriginalTarget
			}
		}
	}
	if err := removeSingBoxSidecar(p); err != nil {
		return err
	}
	cfg.ProtocolEgress = nil
	return nil
}

func validateProtocolEgressRuntime(p *ProtocolEgress) error {
	if p == nil {
		return errors.New("missing protocol egress")
	}
	if !isLoopbackProxyAddress(p.Proxy) {
		return errors.New("protocol egress proxy is not loopback-only")
	}
	if p.SingBoxService == "" || p.SingBoxConfigPath == "" {
		return errors.New("sing-box sidecar service metadata is incomplete")
	}
	clean := filepath.Clean(p.SingBoxConfigPath)
	root := filepath.Clean("/etc/ravanreverse/sing-box") + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" {
		return errors.New("sing-box config path is outside the ShahTunnel state directory")
	}
	if filepath.Base(p.SingBoxService) != p.SingBoxService || !strings.HasPrefix(p.SingBoxService, "shah-tunnel-singbox-") || !strings.HasSuffix(p.SingBoxService, ".service") {
		return errors.New("sing-box service name is not ShahTunnel-managed")
	}
	if p.XrayService == "" || p.XrayConfigPath == "" || len(p.Bindings) == 0 {
		return errors.New("isolated Xray sidecar metadata is incomplete; refusing to start the Agent without mapped user-egress protection")
	}
	xrayClean := filepath.Clean(p.XrayConfigPath)
	xrayRoot := filepath.Clean("/etc/ravanreverse/xray-protocol") + string(os.PathSeparator)
	if !strings.HasPrefix(xrayClean, xrayRoot) || filepath.Base(xrayClean) != "config.json" || filepath.Base(p.XrayService) != p.XrayService || !strings.HasPrefix(p.XrayService, "shah-tunnel-xray-") || !strings.HasSuffix(p.XrayService, ".service") {
		return errors.New("isolated Xray sidecar paths or service name are not ShahTunnel-managed")
	}
	seen := map[string]bool{}
	for _, b := range p.Bindings {
		if b.MappingID == "" || seen[b.MappingID] || !isLoopbackProxyAddress(b.WarpTarget) {
			return errors.New("isolated Xray mapping metadata is invalid")
		}
		if _, _, err := net.SplitHostPort(b.OriginalTarget); err != nil {
			return errors.New("isolated Xray mapping has an invalid original target")
		}
		seen[b.MappingID] = true
	}
	return nil
}

func protocolEgressFingerprint(p *ProtocolEgress) string {
	if p == nil {
		return ""
	}
	b, _ := json.Marshal(struct {
		Protocol, Server string
		Port             int
		UUID             string
	}{p.Protocol, p.Server, p.ServerPort, p.UUID})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
