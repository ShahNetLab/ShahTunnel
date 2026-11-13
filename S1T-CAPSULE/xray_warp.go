package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type xrayRuntime struct {
	PID        int
	Binary     string
	CWD        string
	ConfigPath string
	Service    string
}

var xrayPIDPattern = regexp.MustCompile(`pid=([0-9]+)`)
var xrayServicePattern = regexp.MustCompile(`(?:^|/)([^/]+\.service)(?:/|$)`)

func xrayPortValue(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		p := int(x)
		return p, x == float64(p) && p > 0 && p <= 65535
	case json.Number:
		p, err := strconv.Atoi(string(x))
		return p, err == nil && p > 0 && p <= 65535
	case int:
		return x, x > 0 && x <= 65535
	case string:
		p, err := strconv.Atoi(strings.TrimSpace(x))
		return p, err == nil && p > 0 && p <= 65535
	default:
		return 0, false
	}
}

func xrayConfigHasPort(root map[string]any, port int) int {
	inbounds, _ := root["inbounds"].([]any)
	count := 0
	for _, raw := range inbounds {
		inbound, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		p, ok := xrayPortValue(inbound["port"])
		if ok && p == port {
			count++
		}
	}
	return count
}

func xrayServiceForPID(pid int) (string, error) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		m := xrayServicePattern.FindStringSubmatch(parts[2])
		if len(m) == 2 {
			return m[1], nil
		}
	}
	return "", errors.New("Xray process is not inside a systemd service cgroup")
}

func xrayConfigArgument(args []string, cwd string) (string, error) {
	for i := 1; i < len(args); i++ {
		a := args[i]
		for _, flag := range []string{"-c", "-config", "--config"} {
			if a == flag && i+1 < len(args) {
				p := args[i+1]
				if !filepath.IsAbs(p) {
					p = filepath.Join(cwd, p)
				}
				return filepath.Clean(p), nil
			}
			if strings.HasPrefix(a, flag+"=") {
				p := strings.TrimPrefix(a, flag+"=")
				if !filepath.IsAbs(p) {
					p = filepath.Join(cwd, p)
				}
				return filepath.Clean(p), nil
			}
		}
	}
	p := filepath.Join(cwd, "config.json")
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	return "", errors.New("Xray command line does not expose a config file and no config.json exists in its working directory")
}

func findXrayRuntimeForPort(port int) (xrayRuntime, map[string]any, error) {
	if port < 1 || port > 65535 {
		return xrayRuntime{}, nil, fmt.Errorf("invalid local Xray target port %d", port)
	}
	out, err := exec.Command("ss", "-H", "-lntp", fmt.Sprintf("sport = :%d", port)).CombinedOutput()
	if err != nil {
		return xrayRuntime{}, nil, fmt.Errorf("cannot inspect listener on port %d with ss: %w: %s", port, err, strings.TrimSpace(string(out)))
	}
	matches := xrayPIDPattern.FindAllStringSubmatch(string(out), -1)
	if len(matches) == 0 {
		return xrayRuntime{}, nil, fmt.Errorf("no process PID found listening on local target port %d", port)
	}
	seen := map[int]bool{}
	for _, match := range matches {
		pid, _ := strconv.Atoi(match[1])
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		base := filepath.Join("/proc", strconv.Itoa(pid))
		cmdline, readErr := os.ReadFile(filepath.Join(base, "cmdline"))
		if readErr != nil {
			continue
		}
		var args []string
		for _, part := range bytes.Split(cmdline, []byte{0}) {
			if len(part) > 0 {
				args = append(args, string(part))
			}
		}
		if len(args) == 0 || !strings.Contains(strings.ToLower(filepath.Base(args[0])), "xray") {
			continue
		}
		cwd, cwdErr := os.Readlink(filepath.Join(base, "cwd"))
		if cwdErr != nil {
			continue
		}
		configPath, cfgErr := xrayConfigArgument(args, cwd)
		if cfgErr != nil {
			continue
		}
		configData, cfgReadErr := os.ReadFile(configPath)
		if cfgReadErr != nil {
			continue
		}
		var root map[string]any
		if json.Unmarshal(configData, &root) != nil || xrayConfigHasPort(root, port) == 0 {
			continue
		}
		binary, binErr := os.Readlink(filepath.Join(base, "exe"))
		if binErr != nil || binary == "" {
			binary = args[0]
			if !filepath.IsAbs(binary) {
				binary = filepath.Join(cwd, binary)
			}
		}
		service, serviceErr := xrayServiceForPID(pid)
		if serviceErr != nil {
			return xrayRuntime{}, nil, serviceErr
		}
		if strings.Contains(strings.ToLower(service), "ssh") {
			return xrayRuntime{}, nil, fmt.Errorf("detected Xray cgroup %q looks SSH-related; refusing to restart it", service)
		}
		if _, statErr := os.Stat(binary); statErr != nil {
			return xrayRuntime{}, nil, fmt.Errorf("cannot access running Xray executable %q: %w", binary, statErr)
		}
		return xrayRuntime{PID: pid, Binary: binary, CWD: cwd, ConfigPath: configPath, Service: service}, root, nil
	}
	return xrayRuntime{}, nil, fmt.Errorf("listener on %d is not a discoverable Xray inbound; no Xray config was changed", port)
}

func safeXrayTag(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else if r == '_' || r == '.' || r == ' ' {
			b.WriteByte('-')
		}
	}
	v := strings.Trim(b.String(), "-")
	if v == "" {
		v = "profile"
	}
	if len(v) > 28 {
		v = v[:28]
	}
	return v
}

func allocateXrayLoopbackPort(used map[int]bool) (int, error) {
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		_, pText, _ := net.SplitHostPort(ln.Addr().String())
		p, _ := strconv.Atoi(pText)
		_ = ln.Close()
		if p > 0 && !used[p] {
			used[p] = true
			return p, nil
		}
	}
	return 0, errors.New("could not allocate a unique local Xray inbound port")
}

func cloneJSONMap(src map[string]any) (map[string]any, error) {
	b, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	var dst map[string]any
	if err := json.Unmarshal(b, &dst); err != nil {
		return nil, err
	}
	return dst, nil
}

func buildXrayWarpConfig(original []byte, profileID, proxyAddress string, mappings []PortMapping) ([]byte, []XrayWarpBinding, string, error) {
	return buildXrayEgressConfig(original, profileID, proxyAddress, mappings, "warp", false)
}

// buildXrayEgressConfig creates a private Xray sidecar containing only cloned
// inbounds for the selected ShahTunnel mappings. The original X-UI config is
// never modified. For Psiphon, UDP is explicitly blackholed because its local
// SOCKS proxy is a TCP port-forward proxy and does not implement UDP ASSOCIATE.
func buildXrayEgressConfig(original []byte, profileID, proxyAddress string, mappings []PortMapping, kind string, blockUDP bool) ([]byte, []XrayWarpBinding, string, error) {
	if kind != "warp" && kind != "psiphon" {
		return nil, nil, "", fmt.Errorf("unsupported isolated Xray egress kind %q", kind)
	}
	if _, _, err := net.SplitHostPort(proxyAddress); err != nil || !isLoopbackProxyAddress(proxyAddress) {
		return nil, nil, "", errors.New("isolated Xray SOCKS proxy must be a loopback IP:PORT endpoint")
	}
	var root map[string]any
	if err := json.Unmarshal(original, &root); err != nil {
		return nil, nil, "", fmt.Errorf("Xray config is not plain JSON; refusing to edit it: %w", err)
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		return nil, nil, "", errors.New("Xray config has no inbounds array")
	}
	outbounds, ok := root["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		return nil, nil, "", errors.New("Xray config has no outbounds array")
	}
	usedPorts := map[int]bool{}
	usedTags := map[string]bool{}
	for _, raw := range inbounds {
		if x, ok := raw.(map[string]any); ok {
			if port, ok := xrayPortValue(x["port"]); ok {
				usedPorts[port] = true
			}
			if tag, _ := x["tag"].(string); tag != "" {
				usedTags[tag] = true
			}
		}
	}
	for _, raw := range outbounds {
		if x, ok := raw.(map[string]any); ok {
			if tag, _ := x["tag"].(string); tag != "" {
				usedTags[tag] = true
			}
		}
	}
	shortID := safeXrayTag(profileID)
	outTag := "s1t-" + kind + "-" + shortID + "-out"
	if usedTags[outTag] {
		return nil, nil, "", fmt.Errorf("Xray tag %q already exists; refusing to overwrite it", outTag)
	}
	blockTag := "s1t-" + kind + "-" + shortID + "-udp-block"
	if blockUDP && usedTags[blockTag] {
		return nil, nil, "", fmt.Errorf("Xray tag %q already exists; refusing to overwrite it", blockTag)
	}

	bindings := make([]XrayWarpBinding, 0, len(mappings))
	newInbounds := make([]any, 0, len(mappings))
	newRules := make([]any, 0, len(mappings)*2)
	newInboundTags := make([]string, 0, len(mappings))
	portToBinding := map[int]XrayWarpBinding{}
	for _, mapping := range mappings {
		host, portText, err := net.SplitHostPort(strings.TrimSpace(mapping.Target))
		if err != nil {
			return nil, nil, "", fmt.Errorf("mapping %q target %q is not IP:PORT: %w", mapping.ID, mapping.Target, err)
		}
		ip := net.ParseIP(host)
		if !(strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())) {
			return nil, nil, "", fmt.Errorf("mapping %q target must be loopback for automatic Xray isolation; got %q", mapping.ID, host)
		}
		sourcePort, err := strconv.Atoi(portText)
		if err != nil || sourcePort < 1 || sourcePort > 65535 {
			return nil, nil, "", fmt.Errorf("mapping %q has invalid target port", mapping.ID)
		}
		if existing, ok := portToBinding[sourcePort]; ok {
			b := existing
			b.MappingID = mapping.ID
			b.OriginalTarget = mapping.Target
			bindings = append(bindings, b)
			continue
		}
		var source map[string]any
		for _, raw := range inbounds {
			candidate, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			port, ok := xrayPortValue(candidate["port"])
			if ok && port == sourcePort {
				if source != nil {
					return nil, nil, "", fmt.Errorf("more than one Xray inbound uses port %d; automatic isolation is ambiguous", sourcePort)
				}
				source = candidate
			}
		}
		if source == nil {
			return nil, nil, "", fmt.Errorf("no Xray inbound exists on target port %d", sourcePort)
		}
		port, err := allocateXrayLoopbackPort(usedPorts)
		if err != nil {
			return nil, nil, "", err
		}
		clone, err := cloneJSONMap(source)
		if err != nil {
			return nil, nil, "", err
		}
		inTag := fmt.Sprintf("s1t-%s-%s-%s", kind, shortID, safeXrayTag(mapping.ID))
		if usedTags[inTag] {
			return nil, nil, "", fmt.Errorf("Xray inbound tag %q already exists; refusing to overwrite it", inTag)
		}
		usedTags[inTag] = true
		clone["tag"] = inTag
		clone["listen"] = "127.0.0.1"
		clone["port"] = port
		newInbounds = append(newInbounds, clone)
		newInboundTags = append(newInboundTags, inTag)
		if blockUDP {
			newRules = append(newRules,
				map[string]any{"type": "field", "inboundTag": []any{inTag}, "network": "tcp", "outboundTag": outTag},
				map[string]any{"type": "field", "inboundTag": []any{inTag}, "network": "udp", "outboundTag": blockTag},
				// Any future/unknown network type is blocked as a final fail-closed guard.
				map[string]any{"type": "field", "inboundTag": []any{inTag}, "outboundTag": blockTag},
			)
		} else {
			newRules = append(newRules, map[string]any{"type": "field", "inboundTag": []any{inTag}, "outboundTag": outTag})
		}
		b := XrayWarpBinding{MappingID: mapping.ID, OriginalTarget: mapping.Target, WarpTarget: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), InboundTag: inTag}
		portToBinding[sourcePort] = b
		bindings = append(bindings, b)
	}
	if len(newInbounds) == 0 {
		return nil, nil, "", errors.New("no new Xray inbound routes were created")
	}
	// Run only selected inbound clones in a dedicated Xray sidecar process.
	root["inbounds"] = newInbounds
	delete(root, "api")
	delete(root, "metrics")
	dnsOutbound, dnsRules, err := configureXrayProxyDNS(root, shortID, outTag, newInboundTags, usedTags, kind)
	if err != nil {
		return nil, nil, "", err
	}
	root["outbounds"] = append(outbounds,
		map[string]any{
			"tag": outTag, "protocol": "socks",
			"settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": mustPortNumber(proxyAddress)}}},
		},
		dnsOutbound,
	)
	if blockUDP {
		root["outbounds"] = append(root["outbounds"].([]any), map[string]any{
			"tag": blockTag, "protocol": "blackhole", "settings": map[string]any{"response": map[string]any{"type": "none"}},
		})
	}
	routing, ok := root["routing"].(map[string]any)
	if !ok {
		routing = map[string]any{}
		root["routing"] = routing
	}
	rules, ok := routing["rules"].([]any)
	if !ok && routing["rules"] != nil {
		return nil, nil, "", errors.New("Xray routing.rules is not an array")
	}
	// DNS interception precedes all per-inbound egress and UDP-block rules.
	routing["rules"] = append(append(dnsRules, newRules...), rules...)
	result, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, nil, "", err
	}
	return append(result, '\n'), bindings, outTag, nil
}

// configureXrayWarpDNS mirrors the known-good isolated WARP DNS setup:
// client DNS on port 53 is handed to Xray's DNS module, and the module's own
// DoH requests are routed through the per-profile WARP SOCKS5 outbound.
// This modifies only the generated sidecar config, never the X-UI source JSON.
func configureXrayWarpDNS(root map[string]any, shortID, warpOutboundTag string, inboundTags []string, usedTags map[string]bool) (map[string]any, []any, error) {
	return configureXrayProxyDNS(root, shortID, warpOutboundTag, inboundTags, usedTags, "warp")
}

// configureXrayProxyDNS sends DNS-over-HTTPS requests through the same
// profile-scoped SOCKS5 egress as the cloned client inbounds.
func configureXrayProxyDNS(root map[string]any, shortID, proxyOutboundTag string, inboundTags []string, usedTags map[string]bool, kind string) (map[string]any, []any, error) {
	dnsConfig, ok := root["dns"].(map[string]any)
	if !ok {
		if root["dns"] != nil {
			return nil, nil, errors.New("Xray dns section is not an object")
		}
		dnsConfig = map[string]any{}
		root["dns"] = dnsConfig
	}
	dnsInboundTag, _ := dnsConfig["tag"].(string)
	dnsInboundTag = strings.TrimSpace(dnsInboundTag)
	if dnsInboundTag == "" {
		dnsInboundTag = "s1t-" + kind + "-" + shortID + "-dns-in"
		dnsConfig["tag"] = dnsInboundTag
	}
	dnsOutboundTag := "s1t-" + kind + "-" + shortID + "-dns-out"
	if usedTags[dnsOutboundTag] || dnsOutboundTag == proxyOutboundTag {
		return nil, nil, fmt.Errorf("Xray DNS outbound tag %q already exists; refusing to overwrite it", dnsOutboundTag)
	}
	if len(inboundTags) == 0 {
		return nil, nil, errors.New("no cloned inbound tags available for isolated DNS routing")
	}
	// Provider IPs avoid needing a DNS lookup to bootstrap the DoH connection.
	dnsConfig["servers"] = []any{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}
	dnsConfig["queryStrategy"] = "UseIPv4"
	// Keep Xray's DNS cache enabled so repeat lookups avoid another DoH round trip.
	dnsConfig["disableCache"] = false
	dnsOutbound := map[string]any{"tag": dnsOutboundTag, "protocol": "dns", "settings": map[string]any{}}
	dnsRules := []any{
		map[string]any{
			"type": "field", "inboundTag": stringSliceToAny(inboundTags), "network": "tcp,udp", "port": "53",
			"outboundTag": dnsOutboundTag, "ruleTag": "s1t-" + kind + "-" + shortID + "-dns-hijack",
		},
		map[string]any{
			"type": "field", "inboundTag": []any{dnsInboundTag}, "outboundTag": proxyOutboundTag,
			"ruleTag": "s1t-" + kind + "-" + shortID + "-dns-egress",
		},
	}
	return dnsOutbound, dnsRules, nil
}

func stringSliceToAny(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

func mustPortNumber(address string) int {
	_, p, _ := net.SplitHostPort(address)
	n, _ := strconv.Atoi(p)
	return n
}

func validateXrayConfig(runtime xrayRuntime, configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, runtime.Binary, "run", "-test", "-config", configPath)
	cmd.Dir = runtime.CWD
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Xray rejected the generated configuration: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func atomicReplaceFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".s1t-xray-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func xrayWarpServiceName(profileID string) string {
	return "shah-tunnel-xray-warp-" + tunnelID(profileID) + ".service"
}

func xrayWarpDirectory(profileID string) string {
	return filepath.Join("/etc/ravanreverse/xray-warp", tunnelID(profileID))
}

func systemdExecQuote(value string) string {
	// systemd's ExecStart parser supports double-quoted arguments and C-style
	// backslash escapes. Escape specifiers as well so paths cannot expand %i.
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	return `"` + value + `"`
}

func renderXrayWarpUnit(runtime xrayRuntime, configPath, service string) ([]byte, error) {
	if runtime.Binary == "" || runtime.CWD == "" || configPath == "" ||
		filepath.Base(service) != service || !strings.HasSuffix(service, ".service") {
		return nil, errors.New("invalid Xray WARP sidecar service parameters")
	}
	for _, value := range []string{runtime.Binary, runtime.CWD, configPath} {
		if strings.ContainsAny(value, "\x00\n\r") {
			return nil, errors.New("Xray runtime paths contain unsupported control characters")
		}
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel isolated WARP Xray (%s)
After=network-online.target warp-svc.service
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

[Install]
WantedBy=multi-user.target
`, strings.TrimSuffix(service, ".service"), runtime.CWD, systemdExecQuote(runtime.Binary), systemdExecQuote(configPath))
	return []byte(unit), nil
}

func xrayWarpUnitPath(service string) (string, error) {
	if filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-warp-") || !strings.HasSuffix(service, ".service") {
		return "", fmt.Errorf("refusing to manage non-ShahTunnel WARP unit %q", service)
	}
	return filepath.Join("/etc/systemd/system", service), nil
}

func xrayWarpConfigDirectory(configPath string) (string, error) {
	clean := filepath.Clean(configPath)
	root := filepath.Clean("/etc/ravanreverse/xray-warp") + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" {
		return "", fmt.Errorf("refusing to remove Xray config outside ShahTunnel WARP directory: %q", configPath)
	}
	return filepath.Dir(clean), nil
}

func systemdReload() error {
	out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func xrayWarpJournal(service string) string {
	out, _ := exec.Command("journalctl", "-u", service, "-n", "35", "--no-pager", "-o", "cat").CombinedOutput()
	return strings.TrimSpace(string(out))
}

func waitForXrayWarpInbounds(service string, bindings []XrayWarpBinding) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		allReady := true
		for _, binding := range bindings {
			conn, err := net.DialTimeout("tcp", binding.WarpTarget, 400*time.Millisecond)
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
			return fmt.Errorf("isolated Xray service %s is not active; journal: %s", service, xrayWarpJournal(service))
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("isolated Xray service %s is active but its WARP-only loopback inbounds did not start; journal: %s", service, xrayWarpJournal(service))
}

func installXrayWarpSidecar(runtime xrayRuntime, profileID string, generated []byte, bindings []XrayWarpBinding) (string, string, error) {
	service := xrayWarpServiceName(profileID)
	unitPath, err := xrayWarpUnitPath(service)
	if err != nil {
		return "", "", err
	}
	configDir := xrayWarpDirectory(profileID)
	configPath := filepath.Join(configDir, "config.json")
	if _, err := os.Stat(unitPath); err == nil {
		return "", "", fmt.Errorf("managed WARP Xray unit %s already exists; inspect or remove the previous profile integration first", service)
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
		return "", "", fmt.Errorf("write isolated Xray config: %w", err)
	}
	unit, err := renderXrayWarpUnit(runtime, configPath, service)
	if err != nil {
		cleanup()
		return "", "", err
	}
	if err := os.WriteFile(unitPath, unit, 0644); err != nil {
		cleanup()
		return "", "", fmt.Errorf("write isolated Xray systemd unit: %w", err)
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

func removeXrayWarpSidecar(meta *XrayWarpIntegration) error {
	if meta == nil {
		return nil
	}
	unitPath, err := xrayWarpUnitPath(meta.Service)
	if err != nil {
		return fmt.Errorf("legacy WARP integration needs manual safe migration; refusing to stop or modify %q: %w", meta.Service, err)
	}
	configDir, err := xrayWarpConfigDirectory(meta.ConfigPath)
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

// applyXrayWarpEgress installs the isolated sidecar during new Agent creation.
// The Agent service has not started yet, so it will start only after the
// profile's Xray targets have been switched to the sidecar.
func applyXrayWarpEgress() error {
	if !isRoot() {
		return errors.New("run the manager as root to safely create the dedicated Xray service")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" {
		return errors.New("per-tunnel WARP egress can only be applied to an Agent profile")
	}
	if cfg.Underlay != underlayMASQUE {
		return errors.New("select option 8 / WARP over MASQUE for this Agent profile first")
	}
	if cfg.XrayWARP != nil {
		return errors.New("this tunnel already has a dedicated Xray WARP route")
	}
	proxy, err := verifyWarpPerTunnelPrerequisites()
	if err != nil {
		return err
	}
	var runtime xrayRuntime
	for i, mapping := range cfg.Ports {
		_, portText, splitErr := net.SplitHostPort(mapping.Target)
		if splitErr != nil {
			return fmt.Errorf("mapping %q target must be IP:PORT: %w", mapping.ID, splitErr)
		}
		port, convErr := strconv.Atoi(portText)
		if convErr != nil {
			return fmt.Errorf("mapping %q target port is invalid", mapping.ID)
		}
		rt, _, findErr := findXrayRuntimeForPort(port)
		if findErr != nil {
			return fmt.Errorf("detect Xray for mapping %q: %w", mapping.ID, findErr)
		}
		if i == 0 {
			runtime = rt
		} else if filepath.Clean(runtime.ConfigPath) != filepath.Clean(rt.ConfigPath) || runtime.Binary != rt.Binary || runtime.CWD != rt.CWD {
			return errors.New("all WARP-routed mappings in one tunnel must belong to the same Xray instance")
		}
	}
	originalXray, err := os.ReadFile(runtime.ConfigPath)
	if err != nil {
		return fmt.Errorf("read Xray source config %s: %w", runtime.ConfigPath, err)
	}
	profileID := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	generated, bindings, outTag, err := buildXrayWarpConfig(originalXray, profileID, proxy, cfg.Ports)
	if err != nil {
		return err
	}

	// Validate the sidecar config using the exact Xray executable and working
	// directory used by the X-UI-managed process, without touching its config.
	validateDir := xrayWarpDirectory(profileID)
	if err := os.MkdirAll(validateDir, 0700); err != nil {
		return fmt.Errorf("create Xray WARP state directory: %w", err)
	}
	testFile, err := os.CreateTemp(validateDir, ".config-test-*.json")
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

	// Start a second, profile-scoped Xray process. X-UI can freely regenerate
	// its own config.json; the isolated listener and its port remain separate.
	sidecarConfig, sidecarService, err := installXrayWarpSidecar(runtime, profileID, generated, bindings)
	if err != nil {
		return err
	}
	rollbackSidecar := func() {
		_ = removeXrayWarpSidecar(&XrayWarpIntegration{ConfigPath: sidecarConfig, Service: sidecarService})
	}

	byID := make(map[string]XrayWarpBinding, len(bindings))
	for _, b := range bindings {
		byID[b.MappingID] = b
	}
	for i := range cfg.Ports {
		b, ok := byID[cfg.Ports[i].ID]
		if !ok {
			rollbackSidecar()
			return fmt.Errorf("no isolated Xray binding was generated for mapping %q", cfg.Ports[i].ID)
		}
		cfg.Ports[i].Target = b.WarpTarget
	}
	cfg.XrayWARP = &XrayWarpIntegration{ConfigPath: sidecarConfig, Service: sidecarService, OutboundTag: outTag, Proxy: proxy, Bindings: bindings}
	if err = saveConfig(cfg); err != nil {
		rollbackSidecar()
		return fmt.Errorf("save isolated Agent targets: %w", err)
	}
	uiSuccess("Per-tunnel WARP and DNS are prepared automatically; the new Agent will start on this route.")
	uiInfo("Dedicated Xray service: " + sidecarService)
	uiInfo("X-UI's original config and service were not modified or restarted.")
	uiInfo("Other Xray inbounds and other ShahTunnel profiles remain unchanged.")
	return nil
}

func removeXrayWarpIntegration(cfg *Config) error {
	if cfg == nil || cfg.XrayWARP == nil {
		return nil
	}
	meta := cfg.XrayWARP
	if err := removeXrayWarpSidecar(meta); err != nil {
		return fmt.Errorf("remove dedicated WARP Xray service: %w", err)
	}
	for i := range cfg.Ports {
		for _, binding := range meta.Bindings {
			if cfg.Ports[i].ID == binding.MappingID {
				cfg.Ports[i].Target = binding.OriginalTarget
			}
		}
	}
	cfg.XrayWARP = nil
	return nil
}

// warpProxyForPerTunnelEgressFromSettings rejects host-wide System Tunnel
// mode and accepts only a loopback WarpProxy listener that can isolate one
// Agent profile without touching the host routing table.
func warpProxyForPerTunnelEgressFromSettings(settings string) (string, error) {
	proxy, isProxy, err := warpProxyAddressFromSettings(settings)
	if err != nil {
		return "", err
	}
	if !isProxy || !isLoopbackProxyAddress(proxy) {
		return "", errors.New("Cloudflare is in System Tunnel mode. Per-tunnel WARP egress requires WarpProxy / Local Proxy mode; switch WARP to Local Proxy and reconnect before creating this Agent")
	}
	return proxy, nil
}

// verifyWarpPerTunnelPrerequisites proves that WARP is connected over MASQUE
// and exposes a reachable loopback WarpProxy listener. System-tunnel mode is
// intentionally rejected here: it changes routing at host scope and cannot
// guarantee that only this Agent profile uses WARP.
func verifyWarpPerTunnelPrerequisites() (string, error) {
	if err := verifyWarpMasqueUnderlay(); err != nil {
		return "", err
	}
	warpCLI, err := exec.LookPath("warp-cli")
	if err != nil {
		return "", errors.New("warp-cli is not installed")
	}
	settings, err := runWarpCLI(warpCLI, "settings")
	if err != nil {
		return "", fmt.Errorf("warp-cli settings failed: %w: %s", err, strings.TrimSpace(string(settings)))
	}
	proxy, err := warpProxyForPerTunnelEgressFromSettings(string(settings))
	if err != nil {
		return "", err
	}
	conn, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("Cloudflare WarpProxy listener %s is not reachable: %w", proxy, err)
	}
	_ = conn.Close()
	return proxy, nil
}

// autoApplyXrayWarpForNewAgent installs the isolated WARP sidecar before the
// new Agent service starts. The wizard validates Local Proxy before saving.
func autoApplyXrayWarpForNewAgent() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" || cfg.Underlay != underlayMASQUE || cfg.XrayWARP != nil {
		return nil
	}
	uiInfo("Enabling isolated WARP and WARP-routed DNS automatically before Agent startup…")
	if err := applyXrayWarpEgress(); err != nil {
		return fmt.Errorf("automatic per-tunnel WARP setup failed: %w", err)
	}
	return nil
}
