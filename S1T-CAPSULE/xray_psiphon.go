package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type XrayPsiphonBinding struct {
	MappingID      string `json:"mapping_id"`
	OriginalTarget string `json:"original_target"`
	PsiphonTarget  string `json:"psiphon_target"`
	InboundTag     string `json:"inbound_tag"`
}

type XrayPsiphonIntegration struct {
	ConfigPath  string               `json:"config_path"`
	Service     string               `json:"service"`
	OutboundTag string               `json:"outbound_tag"`
	Proxy       string               `json:"proxy"`
	Bindings    []XrayPsiphonBinding `json:"bindings"`
}

func buildXrayPsiphonConfig(original []byte, profileID, proxyAddress string, mappings []PortMapping) ([]byte, []XrayPsiphonBinding, string, error) {
	generated, warpBindings, outTag, err := buildXrayEgressConfig(original, profileID, proxyAddress, mappings, "psiphon", true)
	if err != nil {
		return nil, nil, "", err
	}
	bindings := make([]XrayPsiphonBinding, 0, len(warpBindings))
	for _, binding := range warpBindings {
		bindings = append(bindings, XrayPsiphonBinding{
			MappingID: binding.MappingID, OriginalTarget: binding.OriginalTarget,
			PsiphonTarget: binding.WarpTarget, InboundTag: binding.InboundTag,
		})
	}
	return generated, bindings, outTag, nil
}

func xrayPsiphonServiceName(profileID string) string {
	return "shah-tunnel-xray-psiphon-" + tunnelID(profileID) + ".service"
}

func xrayPsiphonDirectory(profileID string) string {
	return filepath.Join("/etc/ravanreverse/xray-psiphon", tunnelID(profileID))
}

func xrayPsiphonUnitPath(service string) (string, error) {
	if filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-psiphon-") || !strings.HasSuffix(service, ".service") {
		return "", fmt.Errorf("refusing to manage non-ShahTunnel Psiphon unit %q", service)
	}
	return filepath.Join("/etc/systemd/system", service), nil
}

func xrayPsiphonConfigDirectory(configPath string) (string, error) {
	clean := filepath.Clean(configPath)
	root := filepath.Clean("/etc/ravanreverse/xray-psiphon") + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" {
		return "", fmt.Errorf("refusing to remove Xray config outside ShahTunnel Psiphon directory: %q", configPath)
	}
	return filepath.Dir(clean), nil
}

func renderXrayPsiphonUnit(runtime xrayRuntime, configPath, service string) ([]byte, error) {
	if runtime.Binary == "" || runtime.CWD == "" || configPath == "" ||
		filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-psiphon-") || !strings.HasSuffix(service, ".service") {
		return nil, errors.New("invalid Xray Psiphon sidecar service parameters")
	}
	for _, value := range []string{runtime.Binary, runtime.CWD, configPath} {
		if strings.ContainsAny(value, "\x00\n\r") {
			return nil, errors.New("Xray runtime paths contain unsupported control characters")
		}
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel isolated Psiphon Xray (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s run -config %s
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
KillSignal=SIGINT
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
`, strings.TrimSuffix(service, ".service"), runtime.CWD, systemdExecQuote(runtime.Binary), systemdExecQuote(configPath))
	return []byte(unit), nil
}

func xrayPsiphonJournal(service string) string {
	out, _ := exec.Command("journalctl", "-u", service, "-n", "35", "--no-pager", "-o", "cat").CombinedOutput()
	return strings.TrimSpace(string(out))
}

func waitForXrayPsiphonInbounds(service string, bindings []XrayPsiphonBinding) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		allReady := len(bindings) > 0
		for _, binding := range bindings {
			conn, err := net.DialTimeout("tcp", binding.PsiphonTarget, 400*time.Millisecond)
			if err != nil {
				allReady = false
				break
			}
			_ = conn.Close()
		}
		if allReady {
			return nil
		}
		if exec.Command("systemctl", "is-active", "--quiet", service).Run() != nil {
			return fmt.Errorf("isolated Xray service %s is not active; journal: %s", service, xrayPsiphonJournal(service))
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("isolated Xray service %s is active but its Psiphon-only loopback inbounds did not start; journal: %s", service, xrayPsiphonJournal(service))
}

func installXrayPsiphonSidecar(runtime xrayRuntime, profileID string, generated []byte, bindings []XrayPsiphonBinding) (string, string, error) {
	service := xrayPsiphonServiceName(profileID)
	unitPath, err := xrayPsiphonUnitPath(service)
	if err != nil {
		return "", "", err
	}
	configDir := xrayPsiphonDirectory(profileID)
	configPath := filepath.Join(configDir, "config.json")
	if _, err := os.Stat(unitPath); err == nil {
		return "", "", fmt.Errorf("managed Psiphon Xray unit %s already exists; inspect or remove the previous profile integration first", service)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", err
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", "", err
	}
	cleanup := func() {
		_ = exec.Command("systemctl", "disable", "--now", service).Run()
		_ = os.Remove(unitPath)
		_ = os.RemoveAll(configDir)
		_ = systemdReload()
	}
	if err := atomicReplaceFile(configPath, generated, 0600); err != nil {
		cleanup()
		return "", "", fmt.Errorf("write isolated Psiphon Xray config: %w", err)
	}
	unit, err := renderXrayPsiphonUnit(runtime, configPath, service)
	if err != nil {
		cleanup()
		return "", "", err
	}
	if err := os.WriteFile(unitPath, unit, 0644); err != nil {
		cleanup()
		return "", "", fmt.Errorf("write isolated Psiphon Xray systemd unit: %w", err)
	}
	if err := systemdReload(); err != nil {
		cleanup()
		return "", "", err
	}
	out, err := exec.Command("systemctl", "enable", "--now", service).CombinedOutput()
	if err != nil {
		journal := xrayPsiphonJournal(service)
		cleanup()
		return "", "", fmt.Errorf("start isolated Xray service %s: %w: %s; journal: %s", service, err, strings.TrimSpace(string(out)), journal)
	}
	if err := waitForXrayPsiphonInbounds(service, bindings); err != nil {
		journal := xrayPsiphonJournal(service)
		cleanup()
		return "", "", fmt.Errorf("%w; journal: %s", err, journal)
	}
	return configPath, service, nil
}

func removeXrayPsiphonSidecar(meta *XrayPsiphonIntegration) error {
	if meta == nil {
		return nil
	}
	unitPath, err := xrayPsiphonUnitPath(meta.Service)
	if err != nil {
		return err
	}
	configDir, err := xrayPsiphonConfigDirectory(meta.ConfigPath)
	if err != nil {
		return err
	}
	out, stopErr := exec.Command("systemctl", "disable", "--now", meta.Service).CombinedOutput()
	if stopErr != nil {
		state, _ := exec.Command("systemctl", "show", meta.Service, "-p", "LoadState", "--value").Output()
		if strings.TrimSpace(string(state)) != "not-found" {
			return fmt.Errorf("stop isolated Xray service %s: %w: %s", meta.Service, stopErr, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.RemoveAll(configDir); err != nil {
		return err
	}
	if err := systemdReload(); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "reset-failed", meta.Service).Run()
	return nil
}

// psiphonPublicEgressIP performs a real HTTPS request via the local SOCKS5
// proxy. It is used as a readiness proof, not inferred from the listener alone.
func psiphonPublicEgressIP(proxyAddress string, timeout time.Duration) (string, error) {
	if !isLoopbackProxyAddress(proxyAddress) {
		return "", errors.New("Psiphon proxy must be loopback-only")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialSOCKS5Context(ctx, proxyAddress, address)
		},
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("HTTPS egress test through Psiphon failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Psiphon egress test returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
		return "", fmt.Errorf("Psiphon egress test returned a non-public IP: %q", strings.TrimSpace(string(body)))
	}
	return ip.String(), nil
}

// waitForPsiphonPublicEgressIP tolerates the normal gap between a SOCKS5
// listener opening and the first usable Psiphon tunnel. The listener alone is
// not considered proof of Internet egress.
func waitForPsiphonPublicEgressIP(proxyAddress string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		attemptTimeout := 5 * time.Second
		if remaining < attemptTimeout {
			attemptTimeout = remaining
		}
		ip, err := psiphonPublicEgressIP(proxyAddress, attemptTimeout)
		if err == nil {
			return ip, nil
		}
		lastErr = err
		time.Sleep(1 * time.Second)
	}
	if lastErr != nil {
		return "", fmt.Errorf("Psiphon SOCKS5 is listening but no verified HTTPS egress became available within %s: %w", timeout, lastErr)
	}
	return "", fmt.Errorf("Psiphon HTTPS egress did not become available within %s", timeout)
}

// parsePsiphonEgressGeo accepts only a geolocation response that echoes the
// exact public IP already observed through the Psiphon SOCKS5 connection.
func parsePsiphonEgressGeo(body []byte, expectedIP string) (string, bool) {
	expected := net.ParseIP(strings.TrimSpace(expectedIP))
	if !isPublicIPv4(expected) {
		return "", false
	}
	var payload struct {
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		Country     string `json:"country"`
		Success     *bool  `json:"success"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || strings.EqualFold(payload.Status, "fail") || (payload.Success != nil && !*payload.Success) {
		return "", false
	}
	returned := net.ParseIP(strings.TrimSpace(payload.IP))
	if !isPublicIPv4(returned) || !returned.To4().Equal(expected.To4()) {
		return "", false
	}
	code := strings.ToUpper(strings.TrimSpace(payload.CountryCode))
	if !isAlphaCountryCode(code) {
		country := strings.TrimSpace(payload.Country)
		if isAlphaCountryCode(country) {
			code = strings.ToUpper(country)
		} else if strings.EqualFold(country, "United States") || strings.EqualFold(country, "United States of America") {
			code = "US"
		}
	}
	if !isAlphaCountryCode(code) {
		return "", false
	}
	return code, true
}

// psiphonPublicEgressCountry tries multiple geolocation providers through the
// Psiphon SOCKS5 path. The returned IP must match the actual exit IP; conflicting
// country responses are rejected. Direct-IP lookup is handled separately below.
func psiphonPublicEgressCountry(proxyAddress, exitIP string, timeout time.Duration) (string, error) {
	if !isLoopbackProxyAddress(proxyAddress) {
		return "", errors.New("Psiphon proxy must be loopback-only")
	}
	if !isPublicIPv4(net.ParseIP(exitIP)) {
		return "", fmt.Errorf("invalid Psiphon public exit IP %q", exitIP)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialSOCKS5Context(ctx, proxyAddress, address)
		},
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	endpoints := []string{
		"https://ipapi.co/json/",
		"https://ipwho.is/",
		"https://ipinfo.io/json",
		"https://api.ip.sb/geoip/",
	}
	type result struct {
		country string
		ok      bool
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	results := make(chan result, len(endpoints))
	var wg sync.WaitGroup
	for _, rawURL := range endpoints {
		url := rawURL
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				results <- result{}
				return
			}
			req.Header.Set("User-Agent", "ShahTunnel/"+version)
			req.Header.Set("Accept", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				results <- result{}
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
			_ = resp.Body.Close()
			if readErr != nil || resp.StatusCode != http.StatusOK {
				results <- result{}
				return
			}
			country, ok := parsePsiphonEgressGeo(body, exitIP)
			results <- result{country: country, ok: ok}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	verified := ""
	for {
		select {
		case got, ok := <-results:
			if !ok {
				if verified != "" {
					return verified, nil
				}
				return "", errors.New("no geolocation provider verified the exact Psiphon exit IP through SOCKS")
			}
			if !got.ok {
				continue
			}
			if verified != "" && verified != got.country {
				return "", fmt.Errorf("Psiphon geolocation providers disagree for exit IP %s (%s vs %s)", exitIP, verified, got.country)
			}
			verified = got.country
		case <-ctx.Done():
			if verified != "" {
				return verified, nil
			}
			return "", fmt.Errorf("Psiphon SOCKS geolocation timed out: %w", ctx.Err())
		}
	}
}

// psiphonCountryFromDirectIPLookup performs an independent lookup of the exact
// exit IP obtained through SOCKS. It never looks up the Agent's own IP.
func psiphonCountryFromDirectIPLookup(exitIP string) (string, error) {
	parsed := net.ParseIP(strings.TrimSpace(exitIP))
	if !isPublicIPv4(parsed) {
		return "", fmt.Errorf("expected a public Psiphon exit address, got %q", exitIP)
	}
	expected := parsed.To4().String()
	geo, ok := lookupCountryForIPv4(expected)
	if !ok || !geo.Valid || geo.IP != expected || !isAlphaCountryCode(geo.CountryCode) {
		return "", fmt.Errorf("no independent provider returned a verified country for Psiphon exit IP %s", expected)
	}
	return strings.ToUpper(geo.CountryCode), nil
}

// applyXrayPsiphonEgress builds an independent Xray sidecar and switches only
// the selected Agent's mapping targets. X-UI's source config and system routes
// are never edited. UDP is blocked on this isolated path: Psiphon's local
// SOCKS port-forward proxy carries TCP streams only.
func applyXrayPsiphonEgress(restartAgent, confirm bool) error {
	if !isRoot() {
		return errors.New("run the manager as root to safely create the dedicated Xray service")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" {
		return errors.New("per-tunnel Psiphon user egress can only be applied to an Agent profile")
	}
	if !supportsPsiphonUserEgress(cfg) {
		return errors.New("Psiphon user egress requires an Agent profile using the dedicated Psiphon or all-protocol adaptive option")
	}
	if cfg.XrayPsiphon != nil {
		return errors.New("this tunnel already has a dedicated Xray Psiphon route")
	}
	if cfg.XrayWARP != nil {
		return errors.New("this tunnel already has a dedicated Xray WARP route; remove that integration before selecting Psiphon")
	}
	proxy := strings.TrimSpace(cfg.PsiphonProxy)
	if !isLoopbackProxyAddress(proxy) {
		return errors.New("Agent config does not contain a valid loopback Psiphon SOCKS5 endpoint")
	}
	// Always prove readiness and verify the real exit before creating user
	// egress, including automatic first-time setup after the Agent service starts.
	if err := waitForPsiphonProxy(proxy, 120*time.Second); err != nil {
		return fmt.Errorf("Psiphon SOCKS5 did not become ready at %s: %w; ConsoleClient may still be bootstrapping, so keep the Agent service running and retry", proxy, err)
	}
	ip, err := waitForPsiphonPublicEgressIP(proxy, 90*time.Second)
	if err != nil {
		return err
	}
	country, proxyGeoErr := psiphonPublicEgressCountry(proxy, ip, 10*time.Second)
	if proxyGeoErr != nil {
		// Some relays block geo APIs. Look up the exact public IP observed through
		// SOCKS using multiple independent providers; never classify the Agent IP.
		country, err = psiphonCountryFromDirectIPLookup(ip)
		if err != nil {
			return fmt.Errorf("refusing Psiphon egress because the exact exit IP country could not be verified (SOCKS lookup: %v; independent IP lookup: %w)", proxyGeoErr, err)
		}
		uiWarn(fmt.Sprintf("Psiphon geolocation APIs were unreachable through SOCKS; exact exit IP %s was verified using independent IP lookup (%s).", ip, country))
	}
	if country == "US" || !psiphonAllowedEgressRegions[country] {
		return fmt.Errorf("refusing Psiphon exit %s (%s): US is prohibited and only approved non-US regions are allowed", ip, country)
	}
	var requested psiphonClientConfig
	if raw, readErr := os.ReadFile(cfg.PsiphonConfig); readErr == nil {
		if json.Unmarshal(raw, &requested) == nil {
			if wanted, normalizeErr := normalizePsiphonEgressRegion(requested.EgressRegion); normalizeErr == nil && wanted != country {
				uiWarn(fmt.Sprintf("Psiphon preferred %s but returned an approved alternate exit in %s (%s); continuing because the actual country is allowlisted.", wanted, country, ip))
			}
		}
	}
	uiSuccess(fmt.Sprintf("Verified live Psiphon HTTPS exit IP: %s (country %s)", ip, country))
	if confirm {
		fmt.Println()
		uiWarn("A private Xray sidecar will route only this Agent's mapped user traffic through Psiphon SOCKS5.")
		uiWarn("X-UI source config, other inbounds, other tunnels, SSH and host routes remain unchanged.")
		uiWarn("TCP and DNS use Psiphon. UDP is blocked on this profile to prevent direct-IP leaks; UDP apps and ICMP ping will not work through this SOCKS-only route.")
		if !askYN("Enable Psiphon for users of this Agent tunnel? (y/N)", "n") {
			uiInfo("No changes made.")
			return nil
		}
	}

	oldProfile, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read ShahTunnel profile for transaction: %w", err)
	}
	var runtime xrayRuntime
	for i, mapping := range cfg.Ports {
		_, portText, splitErr := net.SplitHostPort(mapping.Target)
		if splitErr != nil {
			return fmt.Errorf("mapping %q target must be IP:PORT: %w", mapping.ID, splitErr)
		}
		port, convErr := strconv.Atoi(portText)
		if convErr != nil || port < 1 || port > 65535 {
			return fmt.Errorf("mapping %q target port is invalid", mapping.ID)
		}
		rt, _, findErr := findXrayRuntimeForPort(port)
		if findErr != nil {
			return fmt.Errorf("detect Xray for mapping %q: %w", mapping.ID, findErr)
		}
		if i == 0 {
			runtime = rt
		} else if filepath.Clean(runtime.ConfigPath) != filepath.Clean(rt.ConfigPath) || runtime.Binary != rt.Binary || runtime.CWD != rt.CWD {
			return errors.New("all Psiphon-routed mappings in one tunnel must belong to the same Xray instance")
		}
	}
	originalXray, err := os.ReadFile(runtime.ConfigPath)
	if err != nil {
		return fmt.Errorf("read Xray source config %s: %w", runtime.ConfigPath, err)
	}
	profileID := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	generated, bindings, outTag, err := buildXrayPsiphonConfig(originalXray, profileID, proxy, cfg.Ports)
	if err != nil {
		return err
	}
	stateDir := xrayPsiphonDirectory(profileID)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create Xray Psiphon state directory: %w", err)
	}
	testFile, err := os.CreateTemp(stateDir, ".config-test-*.json")
	if err != nil {
		return err
	}
	testPath := testFile.Name()
	if _, err = testFile.Write(generated); err != nil {
		_ = testFile.Close()
		_ = os.Remove(testPath)
		return err
	}
	if err = testFile.Chmod(0600); err != nil {
		_ = testFile.Close()
		_ = os.Remove(testPath)
		return err
	}
	if err = testFile.Close(); err != nil {
		_ = os.Remove(testPath)
		return err
	}
	defer os.Remove(testPath)
	if err = validateXrayConfig(runtime, testPath); err != nil {
		return err
	}

	sidecarConfig, sidecarService, err := installXrayPsiphonSidecar(runtime, profileID, generated, bindings)
	if err != nil {
		return err
	}
	rollbackSidecar := func() {
		_ = removeXrayPsiphonSidecar(&XrayPsiphonIntegration{ConfigPath: sidecarConfig, Service: sidecarService})
	}
	byID := make(map[string]XrayPsiphonBinding, len(bindings))
	for _, binding := range bindings {
		byID[binding.MappingID] = binding
	}
	for i := range cfg.Ports {
		binding, ok := byID[cfg.Ports[i].ID]
		if !ok {
			rollbackSidecar()
			return fmt.Errorf("no isolated Xray Psiphon binding was generated for mapping %q", cfg.Ports[i].ID)
		}
		cfg.Ports[i].Target = binding.PsiphonTarget
	}
	cfg.XrayPsiphon = &XrayPsiphonIntegration{ConfigPath: sidecarConfig, Service: sidecarService, OutboundTag: outTag, Proxy: proxy, Bindings: bindings}
	if err = saveConfig(cfg); err != nil {
		rollbackSidecar()
		return fmt.Errorf("save isolated Agent targets: %w", err)
	}
	if restartAgent {
		service := currentServiceName()
		if err = runSystemctl("restart", service); err != nil {
			_ = atomicReplaceFile(configPath, oldProfile, 0600)
			_ = runSystemctl("restart", service)
			rollbackSidecar()
			return fmt.Errorf("restart ShahTunnel profile %s failed; previous Agent config was restored: %w", service, err)
		}
		// The Agent restart also restarts its PartOf Psiphon unit. Do not report
		// success merely because systemd accepted the restart: wait for the SOCKS
		// listener and a real, newly verified public exit before exposing Xray.
		if err = waitForPsiphonProxy(proxy, 120*time.Second); err == nil {
			var refreshedIP string
			refreshedIP, err = waitForPsiphonPublicEgressIP(proxy, 90*time.Second)
			if err == nil {
				var refreshedCountry string
				refreshedCountry, err = psiphonPublicEgressCountry(proxy, refreshedIP, 10*time.Second)
				if err != nil {
					refreshedCountry, err = psiphonCountryFromDirectIPLookup(refreshedIP)
				}
				if err == nil && (refreshedCountry == "US" || !psiphonAllowedEgressRegions[refreshedCountry]) {
					err = fmt.Errorf("reconnected Psiphon exit %s (%s) is not in the approved non-US country list", refreshedIP, refreshedCountry)
				}
			}
		}
		if err != nil {
			_ = atomicReplaceFile(configPath, oldProfile, 0600)
			_ = runSystemctl("restart", service)
			rollbackSidecar()
			return fmt.Errorf("Psiphon did not recover with a verified approved exit after Agent restart; previous profile was restored: %w", err)
		}
	}
	if restartAgent {
		uiSuccess("Per-tunnel Psiphon TCP egress is active. DNS is also routed through Psiphon; UDP is fail-closed.")
	} else {
		uiSuccess("Per-tunnel Psiphon Xray egress is prepared automatically; the Agent will start on this route.")
	}
	uiInfo("Dedicated Xray service: " + sidecarService)
	uiInfo("X-UI source config, unrelated inbounds, SSH and default routes were not modified.")
	uiInfo("The Psiphon-only route does not provide UDP or ICMP; browser TCP and HTTPS are supported.")
	return nil
}

func removeXrayPsiphonIntegration(cfg *Config) error {
	if cfg == nil || cfg.XrayPsiphon == nil {
		return nil
	}
	meta := cfg.XrayPsiphon
	if err := removeXrayPsiphonSidecar(meta); err != nil {
		return fmt.Errorf("remove dedicated Psiphon Xray service: %w", err)
	}
	for i := range cfg.Ports {
		for _, binding := range meta.Bindings {
			if cfg.Ports[i].ID == binding.MappingID {
				cfg.Ports[i].Target = binding.OriginalTarget
			}
		}
	}
	cfg.XrayPsiphon = nil
	return nil
}

// supportsPsiphonUserEgress identifies Agent modes whose profile-local Psiphon
// SOCKS5 endpoint is provisioned and may safely carry mapped Xray user traffic.
// Option 9 uses the same Psiphon endpoint for user egress while keeping its
// independent adaptive Direct/Psiphon/WARP Agent-to-Hub lane selection.
func supportsPsiphonUserEgress(cfg Config) bool {
	return cfg.Role == "agent" && (cfg.Underlay == underlayPsiphon || cfg.Underlay == underlayAdaptive)
}

func requiresAutomaticPsiphonUserEgress(cfg Config) bool {
	return supportsPsiphonUserEgress(cfg)
}

func autoApplyXrayPsiphonForNewAgent() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if !requiresAutomaticPsiphonUserEgress(cfg) || cfg.XrayPsiphon != nil {
		return nil
	}
	uiInfo("Preparing isolated Xray user egress through the verified per-profile Psiphon SOCKS5 proxy...")
	if err := applyXrayPsiphonEgress(true, false); err != nil {
		return fmt.Errorf("Agent profile was saved, but automatic per-tunnel Psiphon user-egress setup failed: %w", err)
	}
	return nil
}
