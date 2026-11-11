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
			if p, ok := xrayPortValue(x["port"]); ok {
				usedPorts[p] = true
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
	outTag := "s1t-warp-" + shortID + "-out"
	if usedTags[outTag] {
		return nil, nil, "", fmt.Errorf("Xray tag %q already exists; refusing to overwrite it", outTag)
	}

	bindings := make([]XrayWarpBinding, 0, len(mappings))
	newInbounds := make([]any, 0, len(mappings))
	newRules := make([]any, 0, len(mappings))
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
			p, ok := xrayPortValue(candidate["port"])
			if ok && p == sourcePort {
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
		inTag := fmt.Sprintf("s1t-warp-%s-%s", shortID, safeXrayTag(mapping.ID))
		if usedTags[inTag] {
			return nil, nil, "", fmt.Errorf("Xray inbound tag %q already exists; refusing to overwrite it", inTag)
		}
		usedTags[inTag] = true
		clone["tag"] = inTag
		clone["listen"] = "127.0.0.1"
		clone["port"] = port
		newInbounds = append(newInbounds, clone)
		newRules = append(newRules, map[string]any{"type": "field", "inboundTag": []any{inTag}, "outboundTag": outTag})
		b := XrayWarpBinding{MappingID: mapping.ID, OriginalTarget: mapping.Target, WarpTarget: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), InboundTag: inTag}
		portToBinding[sourcePort] = b
		bindings = append(bindings, b)
	}
	if len(newInbounds) == 0 {
		return nil, nil, "", errors.New("no new Xray inbound routes were created")
	}
	root["inbounds"] = append(inbounds, newInbounds...)
	root["outbounds"] = append(outbounds, map[string]any{
		"tag": outTag, "protocol": "socks",
		"settings": map[string]any{"servers": []any{map[string]any{"address": "127.0.0.1", "port": mustPortNumber(proxyAddress)}}},
	})
	routing, ok := root["routing"].(map[string]any)
	if !ok {
		routing = map[string]any{}
		root["routing"] = routing
	}
	rules, ok := routing["rules"].([]any)
	if !ok && routing["rules"] != nil {
		return nil, nil, "", errors.New("Xray routing.rules is not an array")
	}
	routing["rules"] = append(newRules, rules...)
	result, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, nil, "", err
	}
	return append(result, '\n'), bindings, outTag, nil
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

func backupXrayConfig(path string, data []byte, mode os.FileMode, profileID string) (string, error) {
	backup := fmt.Sprintf("%s.s1t-backup-%s-%d", path, safeXrayTag(profileID), time.Now().UnixNano())
	if err := os.WriteFile(backup, data, mode.Perm()); err != nil {
		return "", err
	}
	return backup, nil
}

func restartXrayAndWait(service string, ports []XrayWarpBinding) error {
	out, err := exec.Command("systemctl", "restart", service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart Xray service %s: %w: %s", service, err, strings.TrimSpace(string(out)))
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		allReady := true
		for _, binding := range ports {
			conn, dialErr := net.DialTimeout("tcp", binding.WarpTarget, 400*time.Millisecond)
			if dialErr != nil {
				allReady = false
				break
			}
			_ = conn.Close()
		}
		if allReady {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("Xray restarted but one or more WARP-only loopback inbounds did not start")
}

func applyXrayWarpEgressToSelectedTunnel() error {
	if !isRoot() {
		return errors.New("run the manager as root to safely back up and update Xray")
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
	proxy, isProxy, err := warpProxyAddressFromCLI()
	if err != nil {
		return err
	}
	if !isProxy {
		return errors.New("per-tunnel WARP isolation requires Cloudflare WarpProxy / Local Proxy mode; system-wide WARP routing is intentionally not changed")
	}
	if err := verifyWarpUnderlay("MASQUE"); err != nil {
		return err
	}
	fmt.Println()
	uiWarn("ShahTunnel will clone the selected Xray inbounds to loopback-only ports and route only those cloned inbounds through WARP SOCKS5.")
	uiWarn("The original Xray inbounds and other ShahTunnel profiles (including option 7) remain Direct.")
	uiWarn("Xray and this tunnel service will restart; active client sessions on this Xray instance will briefly disconnect. SSH and host routes are not changed.")
	if !askYN("Apply isolated WARP egress to this tunnel now? (y/N)", "n") {
		uiInfo("No changes made.")
		return nil
	}

	var runtime xrayRuntime
	var originalXray []byte
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
		} else if filepath.Clean(runtime.ConfigPath) != filepath.Clean(rt.ConfigPath) || runtime.Service != rt.Service {
			return errors.New("all WARP-routed mappings in one tunnel must belong to the same Xray instance")
		}
	}
	originalXray, err = os.ReadFile(runtime.ConfigPath)
	if err != nil {
		return fmt.Errorf("read Xray config %s: %w", runtime.ConfigPath, err)
	}
	info, err := os.Stat(runtime.ConfigPath)
	if err != nil {
		return err
	}
	profileID := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	generated, bindings, outTag, err := buildXrayWarpConfig(originalXray, profileID, proxy, cfg.Ports)
	if err != nil {
		return err
	}
	testFile, err := os.CreateTemp(filepath.Dir(runtime.ConfigPath), ".s1t-xray-test-*.json")
	if err != nil {
		return err
	}
	testPath := testFile.Name()
	if _, err = testFile.Write(generated); err != nil {
		_ = testFile.Close()
		_ = os.Remove(testPath)
		return err
	}
	if err = testFile.Chmod(info.Mode().Perm()); err != nil {
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
	backup, err := backupXrayConfig(runtime.ConfigPath, originalXray, info.Mode(), profileID)
	if err != nil {
		return fmt.Errorf("backup Xray config: %w", err)
	}
	if err = atomicReplaceFile(runtime.ConfigPath, generated, info.Mode()); err != nil {
		_ = os.Remove(backup)
		return fmt.Errorf("write Xray config: %w", err)
	}
	if err = restartXrayAndWait(runtime.Service, bindings); err != nil {
		_ = atomicReplaceFile(runtime.ConfigPath, originalXray, info.Mode())
		_, restartErr := exec.Command("systemctl", "restart", runtime.Service).CombinedOutput()
		return fmt.Errorf("Xray WARP activation failed; original config restored from backup %s (rollback restart error=%v): %w", backup, restartErr, err)
	}

	oldProfile, err := os.ReadFile(configPath)
	if err != nil {
		_ = atomicReplaceFile(runtime.ConfigPath, originalXray, info.Mode())
		_, _ = exec.Command("systemctl", "restart", runtime.Service).CombinedOutput()
		return fmt.Errorf("read ShahTunnel profile for transaction: %w", err)
	}
	byID := make(map[string]XrayWarpBinding, len(bindings))
	for _, b := range bindings {
		byID[b.MappingID] = b
	}
	for i := range cfg.Ports {
		b, ok := byID[cfg.Ports[i].ID]
		if !ok {
			continue
		}
		cfg.Ports[i].Target = b.WarpTarget
	}
	cfg.XrayWARP = &XrayWarpIntegration{ConfigPath: runtime.ConfigPath, Service: runtime.Service, OutboundTag: outTag, Proxy: proxy, Bindings: bindings}
	if err = saveConfig(cfg); err != nil {
		_ = atomicReplaceFile(runtime.ConfigPath, originalXray, info.Mode())
		_, _ = exec.Command("systemctl", "restart", runtime.Service).CombinedOutput()
		return fmt.Errorf("save isolated Agent targets: %w", err)
	}
	service := currentServiceName()
	if err = runSystemctl("restart", service); err != nil {
		_ = atomicReplaceFile(configPath, oldProfile, 0600)
		_ = atomicReplaceFile(runtime.ConfigPath, originalXray, info.Mode())
		_, _ = exec.Command("systemctl", "restart", runtime.Service).CombinedOutput()
		return fmt.Errorf("restart ShahTunnel profile %s failed; previous Xray and tunnel configs were restored: %w", service, err)
	}
	uiSuccess("Per-tunnel WARP egress is active. Only this profile's cloned Xray inbound uses WARP SOCKS5.")
	uiInfo("Xray backup: " + backup)
	uiInfo("Other Xray inbounds and option 7 profiles remain unchanged.")
	return nil
}

func removeXrayWarpIntegration(cfg *Config) error {
	if cfg == nil || cfg.XrayWARP == nil {
		return nil
	}
	meta := cfg.XrayWARP
	data, err := os.ReadFile(meta.ConfigPath)
	if err != nil {
		return fmt.Errorf("read Xray config for WARP cleanup: %w", err)
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("parse Xray config for WARP cleanup: %w", err)
	}
	removeTags := map[string]bool{}
	for _, b := range meta.Bindings {
		removeTags[b.InboundTag] = true
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return errors.New("Xray inbounds is not an array")
	}
	keptInbounds := make([]any, 0, len(inbounds))
	for _, raw := range inbounds {
		x, _ := raw.(map[string]any)
		tag, _ := x["tag"].(string)
		if !removeTags[tag] {
			keptInbounds = append(keptInbounds, raw)
		}
	}
	root["inbounds"] = keptInbounds
	routing, _ := root["routing"].(map[string]any)
	if routing != nil {
		if rules, ok := routing["rules"].([]any); ok {
			kept := make([]any, 0, len(rules))
			for _, raw := range rules {
				x, _ := raw.(map[string]any)
				out, _ := x["outboundTag"].(string)
				if out != meta.OutboundTag {
					kept = append(kept, raw)
				}
			}
			routing["rules"] = kept
		}
	}
	if outbounds, ok := root["outbounds"].([]any); ok {
		kept := make([]any, 0, len(outbounds))
		for _, raw := range outbounds {
			x, _ := raw.(map[string]any)
			tag, _ := x["tag"].(string)
			if tag != meta.OutboundTag {
				kept = append(kept, raw)
			}
		}
		root["outbounds"] = kept
	}
	generated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	generated = append(generated, '\n')
	st, err := os.Stat(meta.ConfigPath)
	if err != nil {
		return err
	}
	if _, err = backupXrayConfig(meta.ConfigPath, data, st.Mode(), "cleanup"); err != nil {
		return err
	}
	if err = atomicReplaceFile(meta.ConfigPath, generated, st.Mode()); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "restart", meta.Service)
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = atomicReplaceFile(meta.ConfigPath, data, st.Mode())
		_, _ = exec.Command("systemctl", "restart", meta.Service).CombinedOutput()
		return fmt.Errorf("restart Xray after removing isolated WARP route: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for i := range cfg.Ports {
		for _, b := range meta.Bindings {
			if cfg.Ports[i].ID == b.MappingID {
				cfg.Ports[i].Target = b.OriginalTarget
			}
		}
	}
	cfg.XrayWARP = nil
	return nil
}
