package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	xrayWarpRoot              = "/etc/shah-tunnel/xray-warp"
	warpXrayEgress            = "warp_xray"
	warpXrayOutboundTagPrefix = "shah-warp-egress-"
	warpXrayInboundTagPrefix  = "shah-warp-in-"
)

type xrayWarpMetadata struct {
	ProfileID        string `json:"profile_id"`
	MappingID        string `json:"mapping_id"`
	SourceBinary     string `json:"source_binary"`
	SourceConfig     string `json:"source_config"`
	WorkingDirectory string `json:"working_directory"`
	SourcePort       int    `json:"source_port"`
	SidecarPort      int    `json:"sidecar_port"`
	InboundTag       string `json:"inbound_tag"`
	OutboundTag      string `json:"outbound_tag"`
	ConfigPath       string `json:"config_path"`
	ServiceName      string `json:"service_name"`
}

type xrayRuntime struct {
	Binary  string
	Config  string
	WorkDir string
	Root    map[string]any
}

func profileInstanceID() string {
	base := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "legacy"
	}
	return tunnelID(base)
}

func xrayWarpKey(profileID, mappingID string) string {
	return tunnelID(profileID + "-" + mappingID)
}

func xrayWarpPaths(profileID, mappingID string) (configPath, metaPath, unitPath, serviceName string) {
	key := xrayWarpKey(profileID, mappingID)
	configPath = filepath.Join(xrayWarpRoot, key+".json")
	metaPath = filepath.Join(xrayWarpRoot, key+".meta.json")
	serviceName = "shah-tunnel-xray-warp-" + key + ".service"
	unitPath = filepath.Join("/etc/systemd/system", serviceName)
	return
}

func isLoopbackTargetAddress(address string) (int, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return 0, fmt.Errorf("Xray WARP egress requires a local target IP:PORT: %w", err)
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		ip = net.IPv4(127, 0, 0, 1)
	}
	if ip == nil || !ip.IsLoopback() {
		return 0, fmt.Errorf("Xray WARP sidecar only supports a loopback Xray target; %q is not 127.0.0.1/::1/localhost", host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("Xray target port must be between 1 and 65535")
	}
	return port, nil
}

func configPortMatches(value any, port int) bool {
	switch v := value.(type) {
	case float64:
		return int(v) == port && v == float64(port)
	case int:
		return v == port
	case json.Number:
		n, err := v.Int64()
		return err == nil && int(n) == port
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		return err == nil && n == port
	default:
		return false
	}
}

func findXrayRuntimeForPort(targetPort int) (xrayRuntime, map[string]any, error) {
	var best xrayRuntime
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return best, nil, fmt.Errorf("inspect running Xray process: %w", err)
	}
	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}
		if _, parseErr := strconv.Atoi(entry.Name()); parseErr != nil {
			continue
		}
		pid := entry.Name()
		exePath, readErr := os.Readlink(filepath.Join("/proc", pid, "exe"))
		if readErr != nil || !strings.Contains(strings.ToLower(filepath.Base(exePath)), "xray") || strings.Contains(exePath, "(deleted)") {
			continue
		}
		workDir, _ := os.Readlink(filepath.Join("/proc", pid, "cwd"))
		if workDir == "" || strings.Contains(workDir, "(deleted)") {
			workDir = filepath.Dir(exePath)
		}
		cmdline, readErr := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if readErr != nil {
			continue
		}
		args := strings.Split(string(cmdline), "\x00")
		configFile := findXrayConfigArgument(args, workDir)
		if configFile == "" {
			continue
		}
		root, readErr := readXrayConfig(configFile)
		if readErr != nil {
			continue
		}
		inbounds, _ := root["inbounds"].([]any)
		matches := make([]map[string]any, 0, 1)
		for _, raw := range inbounds {
			candidate, ok := raw.(map[string]any)
			if ok && configPortMatches(candidate["port"], targetPort) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 1 {
			return xrayRuntime{Binary: exePath, Config: configFile, WorkDir: workDir, Root: root}, matches[0], nil
		}
		if len(matches) > 1 {
			return best, nil, fmt.Errorf("Xray config %s has multiple inbounds on port %d; select a unique Xray inbound port", configFile, targetPort)
		}
	}
	return best, nil, fmt.Errorf("could not find a running Xray process with an inbound on target port %d; the WARP client-egress feature requires a local Xray inbound at the selected target", targetPort)
}

func findXrayConfigArgument(args []string, workDir string) string {
	for i := 0; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		var value string
		switch arg {
		case "-c", "-config", "--config":
			if i+1 < len(args) {
				i++
				value = args[i]
			}
		default:
			for _, prefix := range []string{"-c=", "-config=", "--config="} {
				if strings.HasPrefix(arg, prefix) {
					value = strings.TrimPrefix(arg, prefix)
					break
				}
			}
		}
		if value == "" {
			continue
		}
		if !filepath.IsAbs(value) {
			value = filepath.Join(workDir, value)
		}
		value = filepath.Clean(value)
		if st, err := os.Stat(value); err == nil && st.Mode().IsRegular() {
			return value
		}
	}
	return ""
}

func readXrayConfig(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse Xray config %s: %w", path, err)
	}
	if root == nil {
		return nil, fmt.Errorf("Xray config %s is empty", path)
	}
	return root, nil
}

func xraySidecarPort(profileID, mappingID string, originalPort int) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(profileID + ":" + mappingID + ":" + strconv.Itoa(originalPort)))
	return 30000 + int(h.Sum32()%20000)
}

func chooseAvailableSidecarPort(start int) (int, error) {
	for offset := 0; offset < 20000; offset++ {
		port := 30000 + ((start - 30000 + offset) % 20000)
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = ln.Close()
			return port, nil
		}
	}
	return 0, errors.New("no free loopback port is available for the isolated Xray WARP listener")
}

func buildXrayWarpConfig(source map[string]any, sourcePort, sidecarPort int, inboundTag, outboundTag string) ([]byte, error) {
	if sourcePort < 1 || sourcePort > 65535 || sidecarPort < 1 || sidecarPort > 65535 || sourcePort == sidecarPort {
		return nil, errors.New("invalid original or sidecar Xray port")
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return nil, errors.New("Xray config has no inbounds array")
	}
	var selected map[string]any
	for _, item := range inbounds {
		entry, ok := item.(map[string]any)
		if ok && configPortMatches(entry["port"], sourcePort) {
			if selected != nil {
				return nil, fmt.Errorf("Xray config contains more than one inbound on port %d", sourcePort)
			}
			selected = entry
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("Xray inbound port %d was not found in the source config", sourcePort)
	}
	clone := make(map[string]any, len(selected)+2)
	for key, value := range selected {
		clone[key] = value
	}
	clone["listen"] = "127.0.0.1"
	clone["port"] = sidecarPort
	clone["tag"] = inboundTag
	root["inbounds"] = []any{clone}

	outbounds, _ := root["outbounds"].([]any)
	for _, item := range outbounds {
		entry, ok := item.(map[string]any)
		if ok && entry["tag"] == outboundTag {
			return nil, fmt.Errorf("Xray config already contains reserved outbound tag %q", outboundTag)
		}
	}
	root["outbounds"] = append(outbounds, map[string]any{
		"tag":      outboundTag,
		"protocol": "socks",
		"settings": map[string]any{
			"servers": []any{map[string]any{"address": "127.0.0.1", "port": 40000}},
		},
	})

	routing, _ := root["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
		root["routing"] = routing
	}
	rules, _ := routing["rules"].([]any)
	for _, item := range rules {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if entry["outboundTag"] == outboundTag {
			return nil, fmt.Errorf("Xray routing already contains reserved outbound tag %q", outboundTag)
		}
	}
	warpRule := map[string]any{
		"type":        "field",
		"inboundTag":  []any{inboundTag},
		"outboundTag": outboundTag,
	}
	newRules := make([]any, 0, len(rules)+1)
	newRules = append(newRules, warpRule)
	newRules = append(newRules, rules...)
	routing["rules"] = newRules

	// The sidecar must not write into the panel's active access/error log files.
	logConfig, _ := root["log"].(map[string]any)
	if logConfig == nil {
		logConfig = map[string]any{}
		root["log"] = logConfig
	}
	delete(logConfig, "access")
	delete(logConfig, "error")
	if _, ok := logConfig["loglevel"]; !ok {
		logConfig["loglevel"] = "warning"
	}

	result, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(result, '\n'), nil
}

func systemdQuote(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	value = strings.ReplaceAll(value, "%", "%%")
	return "\"" + value + "\""
}

func xrayWarpUnitContent(meta xrayWarpMetadata) string {
	return fmt.Sprintf(`[Unit]
Description=Shah Tunnel isolated Xray WARP egress (%s / %s)
Wants=network-online.target warp-svc.service
After=network-online.target warp-svc.service
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
UMask=0077
ExecStartPre=/usr/local/bin/ravanreverse xray-warp-refresh %s
ExecStartPre=/usr/local/bin/ravanreverse xray-warp-wait
WorkingDirectory=%s
ExecStart=%s run -c %s
Restart=always
RestartSec=3
TimeoutStopSec=20
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectHostname=true
ProtectClock=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
ReadOnlyPaths=%s %s
ReadWritePaths=%s

[Install]
WantedBy=multi-user.target
`, meta.ProfileID, meta.MappingID, systemdQuote(xrayWarpMetaPathForProfile(meta.ProfileID, meta.MappingID)), systemdQuote(meta.WorkingDirectory), systemdQuote(meta.SourceBinary), systemdQuote(meta.ConfigPath), systemdQuote(meta.SourceBinary), systemdQuote(meta.SourceConfig), systemdQuote(filepath.Dir(meta.ConfigPath)))
}

func xrayWarpAgentDropIn(profileID string, serviceNames []string) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Wants=warp-svc.service\nAfter=warp-svc.service\n")
	for _, service := range serviceNames {
		b.WriteString("Requires=" + service + "\n")
		b.WriteString("After=" + service + "\n")
	}
	return b.String()
}

func prepareXrayWarpSidecars(profileID string, ports []PortMapping) ([]PortMapping, error) {
	updated := append([]PortMapping(nil), ports...)
	serviceNames := make([]string, 0)
	prepared := make([]xrayWarpMetadata, 0)
	for i := range updated {
		mapping := &updated[i]
		if mapping.TargetEgress != warpXrayEgress {
			continue
		}
		targetPort, err := isLoopbackTargetAddress(mapping.Target)
		if err != nil {
			return nil, fmt.Errorf("mapping %q: %w", mapping.ID, err)
		}
		runtime, _, err := findXrayRuntimeForPort(targetPort)
		if err != nil {
			return nil, fmt.Errorf("mapping %q: %w", mapping.ID, err)
		}
		cfgPath, metaPath, unitPath, serviceName := xrayWarpPaths(profileID, mapping.ID)
		port := xraySidecarPort(profileID, mapping.ID, targetPort)
		reusedExistingPort := false
		if oldMetaData, readErr := os.ReadFile(metaPath); readErr == nil {
			var old xrayWarpMetadata
			if json.Unmarshal(oldMetaData, &old) == nil && old.SidecarPort >= 30000 && old.SidecarPort <= 49999 && old.SourcePort == targetPort {
				port = old.SidecarPort
				reusedExistingPort = true
			}
		}
		if !reusedExistingPort {
			port, err = chooseAvailableSidecarPort(port)
			if err != nil {
				return nil, err
			}
		}
		if port == targetPort {
			return nil, errors.New("internal Xray WARP sidecar port collision")
		}
		inboundTag := warpXrayInboundTagPrefix + xrayWarpKey(profileID, mapping.ID)
		outboundTag := warpXrayOutboundTagPrefix + xrayWarpKey(profileID, mapping.ID)
		configData, err := buildXrayWarpConfig(runtime.Root, targetPort, port, inboundTag, outboundTag)
		if err != nil {
			return nil, fmt.Errorf("build isolated Xray WARP config for mapping %q: %w", mapping.ID, err)
		}
		if err := os.MkdirAll(xrayWarpRoot, 0700); err != nil {
			return nil, err
		}
		tmpConfig, err := os.CreateTemp(xrayWarpRoot, ".xray-warp-*.json")
		if err != nil {
			return nil, err
		}
		tmpName := tmpConfig.Name()
		if err := tmpConfig.Chmod(0600); err != nil {
			_ = tmpConfig.Close()
			_ = os.Remove(tmpName)
			return nil, err
		}
		if _, err := tmpConfig.Write(configData); err != nil {
			_ = tmpConfig.Close()
			_ = os.Remove(tmpName)
			return nil, err
		}
		if err := tmpConfig.Sync(); err != nil {
			_ = tmpConfig.Close()
			_ = os.Remove(tmpName)
			return nil, err
		}
		if err := tmpConfig.Close(); err != nil {
			_ = os.Remove(tmpName)
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		testCmd := exec.CommandContext(ctx, runtime.Binary, "run", "-test", "-c", tmpName)
		testCmd.Dir = runtime.WorkDir
		out, testErr := testCmd.CombinedOutput()
		cancel()
		if testErr != nil {
			_ = os.Remove(tmpName)
			return nil, fmt.Errorf("Xray rejected the isolated WARP config for mapping %q: %w: %s", mapping.ID, testErr, strings.TrimSpace(string(out)))
		}
		if err := os.Rename(tmpName, cfgPath); err != nil {
			_ = os.Remove(tmpName)
			return nil, err
		}
		meta := xrayWarpMetadata{
			ProfileID: profileID, MappingID: mapping.ID, SourceBinary: runtime.Binary,
			SourceConfig: runtime.Config, WorkingDirectory: runtime.WorkDir,
			SourcePort: targetPort, SidecarPort: port, InboundTag: inboundTag,
			OutboundTag: outboundTag, ConfigPath: cfgPath, ServiceName: serviceName,
		}
		metaData, _ := json.MarshalIndent(meta, "", "  ")
		metaData = append(metaData, '\n')
		if err := atomicWriteFile(metaPath, metaData, 0600); err != nil {
			return nil, err
		}
		unit := xrayWarpUnitContent(meta)
		if err := atomicWriteFile(unitPath, []byte(unit), 0644); err != nil {
			return nil, err
		}
		mapping.WarpTarget = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		serviceNames = append(serviceNames, serviceName)
		prepared = append(prepared, meta)
	}
	if len(serviceNames) == 0 {
		return updated, nil
	}
	sort.Strings(serviceNames)
	dropInDir := filepath.Join("/etc/systemd/system", "ravanreverse@"+profileID+".service.d")
	if err := os.MkdirAll(dropInDir, 0755); err != nil {
		return nil, err
	}
	dropInPath := filepath.Join(dropInDir, "40-shah-tunnel-xray-warp.conf")
	if err := atomicWriteFile(dropInPath, []byte(xrayWarpAgentDropIn(profileID, serviceNames)), 0644); err != nil {
		return nil, err
	}
	return updated, nil
}

func startXrayWarpSidecars(cfg Config, forceRestart bool) error {
	if cfg.Role != "agent" {
		return nil
	}
	services := make([]string, 0)
	for _, mapping := range cfg.Ports {
		if mapping.TargetEgress != warpXrayEgress {
			continue
		}
		if strings.TrimSpace(mapping.WarpTarget) == "" {
			return fmt.Errorf("mapping %q requests WARP Xray egress but has no isolated sidecar target; recreate or repair this Agent profile", mapping.ID)
		}
		_, _, _, serviceName := xrayWarpPaths(profileInstanceID(), mapping.ID)
		services = append(services, serviceName)
	}
	if len(services) == 0 {
		return nil
	}
	if _, err := runOutput(15*time.Second, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd for isolated Xray WARP services: %w", err)
	}
	for _, service := range services {
		if xrayWarpUnitIsActive(service) {
			if forceRestart {
				if _, err := runOutput(45*time.Second, "systemctl", "restart", service); err != nil {
					return fmt.Errorf("refresh/restart isolated Xray WARP service %s: %w", service, err)
				}
			}
		} else if _, err := runOutput(45*time.Second, "systemctl", "enable", "--now", service); err != nil {
			return fmt.Errorf("start isolated Xray WARP service %s: %w", service, err)
		}
	}
	return nil
}

func prepareAgentTargetOverrides(cfg Config) (Config, error) {
	if cfg.Role != "agent" {
		return cfg, nil
	}
	cfg.Ports = append([]PortMapping(nil), cfg.Ports...)
	for i := range cfg.Ports {
		mapping := &cfg.Ports[i]
		if mapping.TargetEgress != warpXrayEgress {
			continue
		}
		if _, err := isLoopbackTargetAddress(mapping.WarpTarget); err != nil {
			return Config{}, fmt.Errorf("mapping %q has an invalid isolated WARP Xray target: %w", mapping.ID, err)
		}
		mapping.Target = mapping.WarpTarget
	}
	return cfg, nil
}

func waitForWarpSOCKSProxy() error {
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := verifySOCKS5ProxyHandshake(warpSOCKSAddress, "", ""); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(1 * time.Second)
	}
	if lastErr != nil {
		return fmt.Errorf("WARP SOCKS5 did not become ready at %s: %w", warpSOCKSAddress, lastErr)
	}
	return fmt.Errorf("WARP SOCKS5 did not become ready at %s", warpSOCKSAddress)
}

func cleanupXrayWarpSidecars(profileID string, ports []PortMapping) error {
	var failures []string
	for _, mapping := range ports {
		if mapping.TargetEgress != warpXrayEgress {
			continue
		}
		_, metaPath, unitPath, serviceName := xrayWarpPaths(profileID, mapping.ID)
		_, err := runOutput(20*time.Second, "systemctl", "disable", "--now", serviceName)
		if err != nil {
			failures = append(failures, serviceName+": "+err.Error())
			continue
		}
		_ = os.Remove(unitPath)
		_ = os.Remove(metaPath)
		configPath, _, _, _ := xrayWarpPaths(profileID, mapping.ID)
		_ = os.Remove(configPath)
	}
	dropInPath := filepath.Join("/etc/systemd/system", "ravanreverse@"+profileID+".service.d", "40-shah-tunnel-xray-warp.conf")
	_ = os.Remove(dropInPath)
	_ = os.Remove(filepath.Join("/etc/systemd/system", "ravanreverse@"+profileID+".service.d"))
	if _, err := runOutput(15*time.Second, "systemctl", "daemon-reload"); err != nil {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func xrayWarpUnitIsActive(serviceName string) bool {
	return exec.Command("systemctl", "is-active", "--quiet", serviceName).Run() == nil
}

func runXrayWarpWaitCommand() error {
	return waitForWarpSOCKSProxy()
}

func xrayWarpCommandUsage() error {
	return errors.New("internal command; use the Shah Tunnel setup wizard")
}

func validateXrayWarpServiceState(mapping PortMapping, profileID string) error {
	if mapping.TargetEgress != warpXrayEgress {
		return nil
	}
	_, _, _, serviceName := xrayWarpPaths(profileID, mapping.ID)
	if !xrayWarpUnitIsActive(serviceName) {
		return fmt.Errorf("isolated Xray WARP service %s is not active", serviceName)
	}
	conn, err := net.DialTimeout("tcp", mapping.WarpTarget, 2*time.Second)
	if err != nil {
		return fmt.Errorf("isolated Xray WARP listener %s is unavailable: %w", mapping.WarpTarget, err)
	}
	_ = conn.Close()
	return nil
}

func readXrayWarpMetadata(path string) (xrayWarpMetadata, error) {
	var meta xrayWarpMetadata
	data, err := os.ReadFile(path)
	if err != nil {
		return meta, err
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return meta, err
	}
	if meta.SourceBinary == "" || meta.SourceConfig == "" || meta.ConfigPath == "" || meta.SourcePort < 1 || meta.SidecarPort < 1 {
		return meta, errors.New("Xray WARP metadata is incomplete")
	}
	return meta, nil
}

func refreshXrayWarpMetadata(metaPath string) error {
	meta, err := readXrayWarpMetadata(metaPath)
	if err != nil {
		return err
	}
	root, err := readXrayConfig(meta.SourceConfig)
	if err != nil {
		return fmt.Errorf("read current panel Xray config: %w", err)
	}
	configData, err := buildXrayWarpConfig(root, meta.SourcePort, meta.SidecarPort, meta.InboundTag, meta.OutboundTag)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(meta.ConfigPath), ".refresh-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(configData); err != nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	testCmd := exec.CommandContext(ctx, meta.SourceBinary, "run", "-test", "-c", tmpPath)
	testCmd.Dir = meta.WorkingDirectory
	out, testErr := testCmd.CombinedOutput()
	cancel()
	if testErr != nil {
		return fmt.Errorf("Xray rejected refreshed WARP config: %w: %s", testErr, strings.TrimSpace(string(out)))
	}
	return os.Rename(tmpPath, meta.ConfigPath)
}

func execXrayWarpRefreshCommand(args []string) error {
	if len(args) != 1 {
		return xrayWarpCommandUsage()
	}
	return refreshXrayWarpMetadata(args[0])
}

func safeXrayConfigPath(path string) bool {
	clean := filepath.Clean(path)
	return filepath.IsAbs(clean) && !strings.Contains(clean, ".."+string(filepath.Separator))
}

func xrayWarpConfigPathForProfile(profileID, mappingID string) string {
	configPath, _, _, _ := xrayWarpPaths(profileID, mappingID)
	return configPath
}

func xrayWarpMetaPathForProfile(profileID, mappingID string) string {
	_, metaPath, _, _ := xrayWarpPaths(profileID, mappingID)
	return metaPath
}

func validateXrayWarpMapping(mapping PortMapping) error {
	if mapping.TargetEgress == "" {
		return nil
	}
	if mapping.TargetEgress != warpXrayEgress {
		return fmt.Errorf("mapping %q has unsupported target egress mode %q", mapping.ID, mapping.TargetEgress)
	}
	if _, err := isLoopbackTargetAddress(mapping.Target); err != nil {
		return err
	}
	if strings.TrimSpace(mapping.WarpTarget) != "" {
		if _, err := isLoopbackTargetAddress(mapping.WarpTarget); err != nil {
			return fmt.Errorf("mapping %q WARP target: %w", mapping.ID, err)
		}
	}
	return nil
}
