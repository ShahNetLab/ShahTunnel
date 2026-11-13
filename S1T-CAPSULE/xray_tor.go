package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type XrayTorBinding struct {
	MappingID      string `json:"mapping_id"`
	OriginalTarget string `json:"original_target"`
	TorTarget      string `json:"tor_target"`
	InboundTag     string `json:"inbound_tag"`
}

type XrayTorIntegration struct {
	ConfigPath  string           `json:"config_path"`
	Service     string           `json:"service"`
	OutboundTag string           `json:"outbound_tag"`
	Proxy       string           `json:"proxy"`
	Bindings    []XrayTorBinding `json:"bindings"`
}

func buildXrayTorConfig(original []byte, profileID, proxyAddress string, mappings []PortMapping) ([]byte, []XrayTorBinding, string, error) {
	generated, proxyBindings, outTag, err := buildXrayEgressConfig(original, profileID, proxyAddress, mappings, "tor", true)
	if err != nil {
		return nil, nil, "", err
	}
	bindings := make([]XrayTorBinding, 0, len(proxyBindings))
	for _, binding := range proxyBindings {
		bindings = append(bindings, XrayTorBinding{
			MappingID: binding.MappingID, OriginalTarget: binding.OriginalTarget,
			TorTarget: binding.WarpTarget, InboundTag: binding.InboundTag,
		})
	}
	return generated, bindings, outTag, nil
}

func xrayTorServiceName(profileID string) string {
	return "shah-tunnel-xray-tor-" + tunnelID(profileID) + ".service"
}

func xrayTorDirectory(profileID string) string {
	return filepath.Join("/etc/ravanreverse/xray-tor", tunnelID(profileID))
}

func xrayTorUnitPath(service string) (string, error) {
	if filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-tor-") || !strings.HasSuffix(service, ".service") {
		return "", fmt.Errorf("refusing to manage non-ShahTunnel Tor Xray unit %q", service)
	}
	return filepath.Join("/etc/systemd/system", service), nil
}

func xrayTorConfigDirectory(configPath string) (string, error) {
	clean := filepath.Clean(configPath)
	root := filepath.Clean("/etc/ravanreverse/xray-tor") + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" {
		return "", fmt.Errorf("refusing to remove Xray config outside ShahTunnel Tor directory: %q", configPath)
	}
	return filepath.Dir(clean), nil
}

func renderXrayTorUnit(runtime xrayRuntime, configPath, service string) ([]byte, error) {
	if runtime.Binary == "" || runtime.CWD == "" || configPath == "" ||
		filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-tor-") || !strings.HasSuffix(service, ".service") {
		return nil, errors.New("invalid Xray Tor sidecar service parameters")
	}
	for _, value := range []string{runtime.Binary, runtime.CWD, configPath} {
		if strings.ContainsAny(value, "\x00\n\r") {
			return nil, errors.New("Xray runtime paths contain unsupported control characters")
		}
	}
	profileService := "ravanreverse@" + tunnelID(filepath.Base(filepath.Dir(configPath))) + ".service"
	if filepath.Base(profileService) != profileService {
		return nil, errors.New("invalid ShahTunnel Agent profile service name for Tor sidecar")
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel isolated Tor Xray (%s)
After=network-online.target %s
PartOf=%s
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
ProtectSystem=full
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
`, strings.TrimSuffix(service, ".service"), profileService, profileService, runtime.CWD, systemdExecQuote(runtime.Binary), systemdExecQuote(configPath))
	return []byte(unit), nil
}

func xrayTorJournal(service string) string {
	out, _ := exec.Command("journalctl", "-u", service, "-n", "35", "--no-pager", "-o", "cat").CombinedOutput()
	return strings.TrimSpace(string(out))
}

func waitForXrayTorInbounds(service string, bindings []XrayTorBinding) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		allReady := len(bindings) > 0
		for _, binding := range bindings {
			conn, err := net.DialTimeout("tcp", binding.TorTarget, 400*time.Millisecond)
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
			return fmt.Errorf("isolated Xray Tor service %s is not active; journal: %s", service, xrayTorJournal(service))
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("isolated Xray Tor service %s is active but its Tor-only loopback inbounds did not start; journal: %s", service, xrayTorJournal(service))
}

func installXrayTorSidecar(runtime xrayRuntime, profileID string, generated []byte, bindings []XrayTorBinding) (string, string, error) {
	service := xrayTorServiceName(profileID)
	unitPath, err := xrayTorUnitPath(service)
	if err != nil {
		return "", "", err
	}
	configDir := xrayTorDirectory(profileID)
	configPath := filepath.Join(configDir, "config.json")
	if _, err := os.Stat(unitPath); err == nil {
		return "", "", fmt.Errorf("managed Tor Xray unit %s already exists; inspect or remove the previous profile integration first", service)
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
		return "", "", fmt.Errorf("write isolated Tor Xray config: %w", err)
	}
	unit, err := renderXrayTorUnit(runtime, configPath, service)
	if err != nil {
		cleanup()
		return "", "", err
	}
	if err := os.WriteFile(unitPath, unit, 0644); err != nil {
		cleanup()
		return "", "", fmt.Errorf("write isolated Tor Xray systemd unit: %w", err)
	}
	if err := systemdReload(); err != nil {
		cleanup()
		return "", "", err
	}
	out, err := exec.Command("systemctl", "enable", "--now", service).CombinedOutput()
	if err != nil {
		journal := xrayTorJournal(service)
		cleanup()
		return "", "", fmt.Errorf("start isolated Xray service %s: %w: %s; journal: %s", service, err, strings.TrimSpace(string(out)), journal)
	}
	if err := waitForXrayTorInbounds(service, bindings); err != nil {
		journal := xrayTorJournal(service)
		cleanup()
		return "", "", fmt.Errorf("%w; journal: %s", err, journal)
	}
	return configPath, service, nil
}

func removeXrayTorSidecar(meta *XrayTorIntegration) error {
	if meta == nil {
		return nil
	}
	unitPath, err := xrayTorUnitPath(meta.Service)
	if err != nil {
		return err
	}
	configDir, err := xrayTorConfigDirectory(meta.ConfigPath)
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

// applyXrayTorEgress creates an independent Xray sidecar for the new Agent.
// Only cloned inbounds for this profile are routed through its private Tor
// SOCKS listener. UDP and unknown networks are blocked to prevent direct leaks.
func applyXrayTorEgress() error {
	if !isRoot() {
		return errors.New("run the manager as root to safely create the dedicated Xray service")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" || cfg.Underlay != underlayTor {
		return errors.New("per-tunnel Tor user egress requires a Tor Agent profile")
	}
	if cfg.XrayTor != nil {
		return errors.New("this tunnel already has a dedicated Xray Tor route")
	}
	if cfg.XrayWARP != nil || cfg.XrayPsiphon != nil {
		return errors.New("remove the existing isolated Xray egress integration before selecting Tor")
	}
	proxy := strings.TrimSpace(cfg.TorProxy)
	if !isLoopbackProxyAddress(proxy) {
		return errors.New("Agent config does not contain a valid loopback Tor SOCKS5 endpoint")
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
			return errors.New("all Tor-routed mappings in one tunnel must belong to the same Xray instance")
		}
	}
	originalXray, err := os.ReadFile(runtime.ConfigPath)
	if err != nil {
		return fmt.Errorf("read Xray source config %s: %w", runtime.ConfigPath, err)
	}
	profileID := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	generated, bindings, outTag, err := buildXrayTorConfig(originalXray, profileID, proxy, cfg.Ports)
	if err != nil {
		return err
	}
	stateDir := xrayTorDirectory(profileID)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create Xray Tor state directory: %w", err)
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

	sidecarConfig, sidecarService, err := installXrayTorSidecar(runtime, profileID, generated, bindings)
	if err != nil {
		return err
	}
	rollbackSidecar := func() {
		_ = removeXrayTorSidecar(&XrayTorIntegration{ConfigPath: sidecarConfig, Service: sidecarService})
	}
	byID := make(map[string]XrayTorBinding, len(bindings))
	for _, binding := range bindings {
		byID[binding.MappingID] = binding
	}
	for i := range cfg.Ports {
		binding, ok := byID[cfg.Ports[i].ID]
		if !ok {
			rollbackSidecar()
			return fmt.Errorf("no isolated Xray Tor binding was generated for mapping %q", cfg.Ports[i].ID)
		}
		cfg.Ports[i].Target = binding.TorTarget
	}
	cfg.XrayTor = &XrayTorIntegration{ConfigPath: sidecarConfig, Service: sidecarService, OutboundTag: outTag, Proxy: proxy, Bindings: bindings}
	if err = saveConfig(cfg); err != nil {
		rollbackSidecar()
		return fmt.Errorf("save isolated Agent targets: %w", err)
	}
	uiSuccess("Per-tunnel Tor TCP/DNS egress is prepared automatically for this Agent.")
	uiInfo("Dedicated Xray service: " + sidecarService)
	uiInfo("Only this Agent's cloned Xray inbounds use Tor. X-UI's original config, other inbounds, SSH and host routes remain unchanged.")
	uiInfo("UDP and unknown protocols are blocked on this Tor-only route; UDP applications, QUIC and ICMP are unavailable.")
	return nil
}

func removeXrayTorIntegration(cfg *Config) error {
	if cfg == nil || cfg.XrayTor == nil {
		return nil
	}
	meta := cfg.XrayTor
	if err := removeXrayTorSidecar(meta); err != nil {
		return fmt.Errorf("remove dedicated Tor Xray service: %w", err)
	}
	for i := range cfg.Ports {
		for _, binding := range meta.Bindings {
			if cfg.Ports[i].ID == binding.MappingID {
				cfg.Ports[i].Target = binding.OriginalTarget
			}
		}
	}
	cfg.XrayTor = nil
	return nil
}

// rollbackFailedTorAgentSetup removes only the just-created Tor Agent profile
// and its private Tor state when automatic Xray egress provisioning fails.
// It deliberately refuses paths outside the exact ShahTunnel profile roots.
func rollbackFailedTorAgentSetup(profileConfigPath string, cfg Config) error {
	profileID := tunnelID(cfg.Name)
	configPath := filepath.Clean(profileConfigPath)
	if filepath.Dir(configPath) != filepath.Clean(tunnelConfigDir) || filepath.Ext(configPath) != ".json" {
		return fmt.Errorf("refusing to roll back an unexpected tunnel config path %q", profileConfigPath)
	}
	expectedDataDir := filepath.Join(torDataRoot, profileID)
	if filepath.Clean(cfg.TorDataDir) != filepath.Clean(expectedDataDir) {
		return fmt.Errorf("refusing to roll back unexpected Tor data directory %q", cfg.TorDataDir)
	}
	expectedTorConfig := filepath.Join(torConfigDir, profileID+".torrc")
	if cfg.TorConfigPath != "" && filepath.Clean(cfg.TorConfigPath) != filepath.Clean(expectedTorConfig) {
		return fmt.Errorf("refusing to roll back unexpected Tor config path %q", cfg.TorConfigPath)
	}
	if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove incomplete Agent profile config: %w", err)
	}
	if err := os.RemoveAll(expectedDataDir); err != nil {
		return fmt.Errorf("remove incomplete Tor profile data: %w", err)
	}
	if err := os.Remove(expectedTorConfig); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove incomplete Tor profile config: %w", err)
	}
	return nil
}

func autoApplyXrayTorForNewAgent() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" || cfg.Underlay != underlayTor || cfg.XrayTor != nil {
		return nil
	}
	uiInfo("Preparing isolated Xray user TCP/DNS egress through the Agent's private Tor SOCKS5 proxy...")
	if err := applyXrayTorEgress(); err != nil {
		return fmt.Errorf("Agent profile was saved, but automatic per-tunnel Tor user-egress setup failed: %w", err)
	}
	return nil
}
