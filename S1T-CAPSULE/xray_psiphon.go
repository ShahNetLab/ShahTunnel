package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

// adaptiveWarpProxyAddress returns only a loopback WarpProxy/Local Proxy
// endpoint. System Tunnel mode is intentionally excluded because it would
// change the host-wide route instead of isolating this ShahTunnel profile.
func adaptiveWarpProxyAddress() string {
	warpCLI, err := exec.LookPath("warp-cli")
	if err != nil {
		return ""
	}
	settings, err := runWarpCLI(warpCLI, "settings")
	if err != nil || !warpProtocolMatches(string(settings), "MASQUE") {
		return ""
	}
	proxy, localProxy, err := warpProxyAddressFromSettings(string(settings))
	if err != nil || !localProxy || !isLoopbackProxyAddress(proxy) {
		return ""
	}
	// Do not require the listener to answer at Agent startup. Xray's
	// Observatory probes it continuously and can promote it when WARP comes
	// online later; an unavailable proxy is simply marked unhealthy meanwhile.
	return proxy
}

// addXrayAdaptiveEgressBalancer turns an already isolated Psiphon sidecar into
// a health-aware egress group. Psiphon and an available per-app WARP proxy are
// tested independently; Xray selects the lowest-latency healthy path. If all
// external egresses fail, traffic is blackholed rather than sent directly.
func addXrayAdaptiveEgressBalancer(generated []byte, profileID, psiphonOutboundTag, warpProxy string) ([]byte, string, error) {
	var root map[string]any
	if err := json.Unmarshal(generated, &root); err != nil {
		return nil, "", fmt.Errorf("parse isolated Xray Psiphon config: %w", err)
	}
	outbounds, ok := root["outbounds"].([]any)
	if !ok {
		return nil, "", errors.New("isolated Xray config has no outbounds array")
	}
	shortID := safeXrayTag(profileID)
	warpTag := "s1t-adaptive-" + shortID + "-warp"
	blockTag := "s1t-adaptive-" + shortID + "-block"
	balancerTag := "s1t-adaptive-" + shortID + "-best"
	hasPsiphon := false
	usedTags := map[string]bool{}
	for _, raw := range outbounds {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := item["tag"].(string)
		if tag != "" {
			usedTags[tag] = true
		}
		if tag == psiphonOutboundTag {
			hasPsiphon = true
		}
	}
	if !hasPsiphon {
		return nil, "", fmt.Errorf("Psiphon outbound %q is missing", psiphonOutboundTag)
	}
	for _, tag := range []string{warpTag, blockTag} {
		if usedTags[tag] {
			return nil, "", fmt.Errorf("Xray tag %q already exists; refusing to overwrite it", tag)
		}
	}
	selectors := []any{psiphonOutboundTag}
	if strings.TrimSpace(warpProxy) != "" {
		if _, _, err := net.SplitHostPort(warpProxy); err != nil || !isLoopbackProxyAddress(warpProxy) {
			return nil, "", errors.New("adaptive WARP proxy must be a loopback IP:PORT endpoint")
		}
		outbounds = append(outbounds, map[string]any{
			"tag": warpTag, "protocol": "socks",
			"settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": mustPortNumber(warpProxy)}}},
		})
		selectors = append(selectors, warpTag)
	}
	outbounds = append(outbounds, map[string]any{
		"tag": blockTag, "protocol": "blackhole", "settings": map[string]any{"response": map[string]any{"type": "none"}},
	})
	root["outbounds"] = outbounds

	routing, ok := root["routing"].(map[string]any)
	if !ok {
		routing = map[string]any{}
		root["routing"] = routing
	}
	rules, ok := routing["rules"].([]any)
	if !ok {
		return nil, "", errors.New("Xray routing.rules is not an array")
	}
	replaced := 0
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if target, _ := rule["outboundTag"].(string); target == psiphonOutboundTag {
			delete(rule, "outboundTag")
			rule["balancerTag"] = balancerTag
			replaced++
		}
	}
	if replaced < 2 {
		return nil, "", fmt.Errorf("expected TCP and DNS rules for Psiphon, found only %d", replaced)
	}
	balancers, ok := routing["balancers"].([]any)
	if !ok && routing["balancers"] != nil {
		return nil, "", errors.New("Xray routing.balancers is not an array")
	}
	for _, raw := range balancers {
		if item, ok := raw.(map[string]any); ok {
			if tag, _ := item["tag"].(string); tag == balancerTag {
				return nil, "", fmt.Errorf("Xray balancer tag %q already exists", balancerTag)
			}
		}
	}
	balancers = append(balancers, map[string]any{
		"tag":         balancerTag,
		"selector":    selectors,
		"fallbackTag": blockTag,
		"strategy":    map[string]any{"type": "leastPing"},
	})
	routing["balancers"] = balancers

	observatory, ok := root["observatory"].(map[string]any)
	if !ok {
		if root["observatory"] != nil {
			return nil, "", errors.New("Xray observatory section is not an object")
		}
		observatory = map[string]any{}
		root["observatory"] = observatory
	}
	observatory["subjectSelector"] = selectors
	observatory["probeUrl"] = "https://www.cloudflare.com/cdn-cgi/trace"
	observatory["probeInterval"] = "20s"
	observatory["enableConcurrency"] = true

	result, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, "", err
	}
	return append(result, '\n'), balancerTag, nil
}

func buildXrayAdaptivePsiphonConfig(original []byte, profileID, psiphonProxy, warpProxy string, mappings []PortMapping) ([]byte, []XrayPsiphonBinding, string, string, error) {
	base, bindings, psiphonTag, err := buildXrayPsiphonConfig(original, profileID, psiphonProxy, mappings)
	if err != nil {
		return nil, nil, "", "", err
	}
	generated, balancerTag, err := addXrayAdaptiveEgressBalancer(base, profileID, psiphonTag, warpProxy)
	if err != nil {
		return nil, nil, "", "", err
	}
	return generated, bindings, balancerTag, psiphonTag, nil
}

// preserveXraySidecarPorts keeps already-published loopback target ports stable
// while regenerating the isolated sidecar. No Hub mapping or client port changes.
func preserveXraySidecarPorts(generated []byte, fresh, previous []XrayPsiphonBinding) ([]byte, []XrayPsiphonBinding, error) {
	oldByID := make(map[string]string, len(previous))
	for _, item := range previous {
		oldByID[item.MappingID] = item.PsiphonTarget
	}
	var root map[string]any
	if err := json.Unmarshal(generated, &root); err != nil {
		return nil, nil, err
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return nil, nil, errors.New("adaptive Xray config has no inbounds array")
	}
	used := map[string]string{}
	updated := append([]XrayPsiphonBinding(nil), fresh...)
	for i := range updated {
		oldTarget := oldByID[updated[i].MappingID]
		host, portText, err := net.SplitHostPort(oldTarget)
		if err != nil || !isLoopbackProxyAddress(oldTarget) {
			return nil, nil, fmt.Errorf("existing sidecar target for %q is not loopback IP:PORT", updated[i].MappingID)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, nil, fmt.Errorf("existing sidecar target for %q has invalid port", updated[i].MappingID)
		}
		if other, exists := used[oldTarget]; exists && other != updated[i].InboundTag {
			return nil, nil, fmt.Errorf("existing sidecar port %s is shared by different inbound tags", oldTarget)
		}
		used[oldTarget] = updated[i].InboundTag
		found := false
		for _, raw := range inbounds {
			inbound, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if tag, _ := inbound["tag"].(string); tag == updated[i].InboundTag {
				inbound["listen"] = host
				inbound["port"] = port
				found = true
				break
			}
		}
		if !found {
			return nil, nil, fmt.Errorf("generated Xray inbound %q is missing", updated[i].InboundTag)
		}
		updated[i].PsiphonTarget = oldTarget
	}
	result, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return append(result, '\n'), updated, nil
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
	if cfg.Underlay != underlayPsiphon && cfg.Underlay != underlayAdaptive {
		return errors.New("select Psiphon SOCKS5 egress for this Agent profile first")
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
	if restartAgent {
		if err := probeSOCKS5(proxy, 2*time.Second); err != nil {
			return fmt.Errorf("Psiphon SOCKS5 is not ready at %s: %w; start the Agent/Psiphon service first", proxy, err)
		}
		ip, err := psiphonPublicEgressIP(proxy, 12*time.Second)
		if err != nil {
			return err
		}
		uiSuccess("Verified live Psiphon HTTPS exit IP: " + ip)
	}
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
	var generated []byte
	var bindings []XrayPsiphonBinding
	var outTag string
	if cfg.Underlay == underlayAdaptive {
		warpProxy := adaptiveWarpProxyAddress()
		var psiphonTag string
		generated, bindings, outTag, psiphonTag, err = buildXrayAdaptivePsiphonConfig(originalXray, profileID, proxy, warpProxy, cfg.Ports)
		if err == nil {
			if warpProxy != "" {
				uiInfo("Option 9 Xray egress candidates: Psiphon + WARP Local Proxy; Xray leastPing health checks are enabled.")
			} else {
				uiInfo("Option 9: no connected per-app WARP Local Proxy detected; Psiphon remains the only external Xray egress candidate until WARP Local Proxy is configured.")
			}
			_ = psiphonTag
		}
	} else {
		generated, bindings, outTag, err = buildXrayPsiphonConfig(originalXray, profileID, proxy, cfg.Ports)
	}
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

// ensureAdaptiveXrayPsiphonEgress upgrades an already-installed option-9
// Psiphon-only sidecar in place. It never edits the X-UI source config, never
// changes the published loopback target ports, and restores the previous
// sidecar file if validation or restart fails.
func ensureAdaptiveXrayPsiphonEgress(cfg Config) error {
	if cfg.Role != "agent" || cfg.Underlay != underlayAdaptive || cfg.XrayPsiphon == nil {
		return nil
	}
	meta := cfg.XrayPsiphon
	if _, err := xrayPsiphonUnitPath(meta.Service); err != nil {
		return err
	}
	if _, err := xrayPsiphonConfigDirectory(meta.ConfigPath); err != nil {
		return err
	}
	originalMappings := make([]PortMapping, 0, len(meta.Bindings))
	var runtime xrayRuntime
	for i, binding := range meta.Bindings {
		_, portText, err := net.SplitHostPort(binding.OriginalTarget)
		if err != nil {
			return fmt.Errorf("original Xray target for mapping %q is invalid: %w", binding.MappingID, err)
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("original Xray target for mapping %q has invalid port", binding.MappingID)
		}
		rt, _, findErr := findXrayRuntimeForPort(port)
		if findErr != nil {
			return fmt.Errorf("find original Xray runtime for mapping %q: %w", binding.MappingID, findErr)
		}
		if i == 0 {
			runtime = rt
		} else if runtime.ConfigPath != rt.ConfigPath || runtime.Binary != rt.Binary || runtime.CWD != rt.CWD {
			return errors.New("adaptive egress mappings belong to different Xray instances")
		}
		originalMappings = append(originalMappings, PortMapping{ID: binding.MappingID, Target: binding.OriginalTarget})
	}
	if len(originalMappings) == 0 {
		return errors.New("adaptive Xray integration has no saved original mappings")
	}
	originalXray, err := os.ReadFile(runtime.ConfigPath)
	if err != nil {
		return fmt.Errorf("read original Xray config: %w", err)
	}
	warpProxy := adaptiveWarpProxyAddress()
	generated, freshBindings, balancerTag, _, err := buildXrayAdaptivePsiphonConfig(originalXray, strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath)), cfg.PsiphonProxy, warpProxy, originalMappings)
	if err != nil {
		return err
	}
	generated, freshBindings, err = preserveXraySidecarPorts(generated, freshBindings, meta.Bindings)
	if err != nil {
		return err
	}

	stateDir := filepath.Dir(meta.ConfigPath)
	testFile, err := os.CreateTemp(stateDir, ".adaptive-config-test-*.json")
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
		return fmt.Errorf("installed Xray rejected adaptive leastPing config; existing Psiphon sidecar was kept: %w", err)
	}

	previous, err := os.ReadFile(meta.ConfigPath)
	if err != nil {
		return fmt.Errorf("read current Xray sidecar config: %w", err)
	}
	if bytes.Equal(previous, generated) {
		log.Printf("adaptive Xray egress already configured; candidates=%s", adaptiveXrayCandidateSummary(warpProxy))
		return nil
	}
	if err := atomicReplaceFile(meta.ConfigPath, generated, 0600); err != nil {
		return fmt.Errorf("write adaptive Xray sidecar config: %w", err)
	}
	restore := func() {
		_ = atomicReplaceFile(meta.ConfigPath, previous, 0600)
		_ = exec.Command("systemctl", "restart", meta.Service).Run()
	}
	out, restartErr := exec.Command("systemctl", "restart", meta.Service).CombinedOutput()
	if restartErr != nil {
		restore()
		return fmt.Errorf("restart adaptive Xray sidecar %s: %w: %s; previous config restored", meta.Service, restartErr, strings.TrimSpace(string(out)))
	}
	if err := waitForXrayPsiphonInbounds(meta.Service, freshBindings); err != nil {
		restore()
		return fmt.Errorf("adaptive Xray sidecar health check failed; previous config restored: %w", err)
	}
	log.Printf("adaptive Xray egress active: %s; balancer=%s; probe interval=20s; fallback=blackhole", adaptiveXrayCandidateSummary(warpProxy), balancerTag)
	return nil
}

func adaptiveXrayCandidateSummary(warpProxy string) string {
	if strings.TrimSpace(warpProxy) != "" {
		return "Psiphon + WARP Local Proxy (leastPing)"
	}
	return "Psiphon only (WARP Local Proxy unavailable; fail-closed)"
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

func autoApplyXrayPsiphonForNewAgent() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" || (cfg.Underlay != underlayPsiphon && cfg.Underlay != underlayAdaptive) || cfg.XrayPsiphon != nil {
		return nil
	}
	if cfg.Underlay == underlayAdaptive {
		uiInfo("Preparing isolated Xray user egress with automatic Psiphon/WARP leastPing selection (fail-closed; no direct IP fallback)...")
	} else {
		uiInfo("Preparing isolated Xray user egress through the Agent's Psiphon SOCKS5 proxy...")
	}
	if err := applyXrayPsiphonEgress(false, false); err != nil {
		return fmt.Errorf("Agent profile was saved, but automatic per-tunnel Psiphon user-egress setup failed: %w", err)
	}
	return nil
}
