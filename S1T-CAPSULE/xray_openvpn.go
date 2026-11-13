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

type XrayOpenVPNBinding struct {
	MappingID      string `json:"mapping_id"`
	OriginalTarget string `json:"original_target"`
	OpenVPNTarget  string `json:"openvpn_target"`
	InboundTag     string `json:"inbound_tag"`
}

type XrayOpenVPNIntegration struct {
	ConfigPath  string               `json:"config_path"`
	Service     string               `json:"service"`
	OutboundTag string               `json:"outbound_tag"`
	Mark        int                  `json:"mark"`
	Bindings    []XrayOpenVPNBinding `json:"bindings"`
}

func buildXrayOpenVPNConfig(original []byte, profileID string, mark int, mappings []PortMapping) ([]byte, []XrayOpenVPNBinding, string, error) {
	generated, rawBindings, outTag, err := buildXrayEgressConfig(original, profileID, "", mappings, "openvpn", false, mark)
	if err != nil {
		return nil, nil, "", err
	}
	bindings := make([]XrayOpenVPNBinding, 0, len(rawBindings))
	for _, b := range rawBindings {
		bindings = append(bindings, XrayOpenVPNBinding{MappingID: b.MappingID, OriginalTarget: b.OriginalTarget, OpenVPNTarget: b.WarpTarget, InboundTag: b.InboundTag})
	}
	return generated, bindings, outTag, nil
}

func xrayOpenVPNServiceName(profile string) string {
	return "shah-tunnel-xray-openvpn-" + tunnelID(profile) + ".service"
}
func xrayOpenVPNDir(profile string) string {
	return filepath.Join("/etc/ravanreverse/xray-openvpn", tunnelID(profile))
}
func xrayOpenVPNUnitPath(service string) (string, error) {
	if filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-openvpn-") || !strings.HasSuffix(service, ".service") {
		return "", fmt.Errorf("refusing to manage non-ShahTunnel OpenVPN Xray unit %q", service)
	}
	return filepath.Join("/etc/systemd/system", service), nil
}
func xrayOpenVPNConfigDir(config string) (string, error) {
	clean := filepath.Clean(config)
	root := filepath.Clean("/etc/ravanreverse/xray-openvpn") + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) || filepath.Base(clean) != "config.json" {
		return "", fmt.Errorf("refusing to remove Xray config outside ShahTunnel OpenVPN directory: %q", config)
	}
	return filepath.Dir(clean), nil
}
func renderXrayOpenVPNUnit(runtime xrayRuntime, configPath, service, openVPNService string) ([]byte, error) {
	if runtime.Binary == "" || runtime.CWD == "" || configPath == "" || filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-xray-openvpn-") {
		return nil, errors.New("invalid OpenVPN Xray sidecar service parameters")
	}
	for _, v := range []string{runtime.Binary, runtime.CWD, configPath, openVPNService} {
		if strings.ContainsAny(v, "\x00\n\r") {
			return nil, errors.New("OpenVPN Xray service paths contain unsupported control characters")
		}
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel isolated OpenVPN Xray egress (%s)
After=network-online.target %s
Wants=network-online.target
Requires=%s

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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK

[Install]
WantedBy=multi-user.target
`, strings.TrimSuffix(service, ".service"), openVPNService, openVPNService, runtime.CWD, systemdExecQuote(runtime.Binary), systemdExecQuote(configPath))
	return []byte(unit), nil
}
func xrayOpenVPNJournal(service string) string {
	out, _ := exec.Command("journalctl", "-u", service, "-n", "35", "--no-pager", "-o", "cat").CombinedOutput()
	return strings.TrimSpace(string(out))
}
func waitForXrayOpenVPNInbounds(service string, bindings []XrayOpenVPNBinding) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		all := len(bindings) > 0
		for _, b := range bindings {
			c, e := net.DialTimeout("tcp", b.OpenVPNTarget, 400*time.Millisecond)
			if e != nil {
				all = false
				break
			}
			_ = c.Close()
		}
		if all {
			return nil
		}
		if exec.Command("systemctl", "is-active", "--quiet", service).Run() != nil {
			return fmt.Errorf("isolated OpenVPN Xray service %s is not active; journal: %s", service, xrayOpenVPNJournal(service))
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("isolated OpenVPN Xray service %s did not start all loopback inbounds; journal: %s", service, xrayOpenVPNJournal(service))
}
func installXrayOpenVPNSidecar(runtime xrayRuntime, profile string, generated []byte, bindings []XrayOpenVPNBinding, openVPNService string) (string, string, error) {
	service := xrayOpenVPNServiceName(profile)
	unitPath, err := xrayOpenVPNUnitPath(service)
	if err != nil {
		return "", "", err
	}
	configDir := xrayOpenVPNDir(profile)
	configPath := filepath.Join(configDir, "config.json")
	if _, err = os.Stat(unitPath); err == nil {
		return "", "", fmt.Errorf("managed OpenVPN Xray unit %s already exists", service)
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
		return "", "", fmt.Errorf("write isolated OpenVPN Xray config: %w", err)
	}
	unit, err := renderXrayOpenVPNUnit(runtime, configPath, service, openVPNService)
	if err != nil {
		cleanup()
		return "", "", err
	}
	if err := os.WriteFile(unitPath, unit, 0644); err != nil {
		cleanup()
		return "", "", err
	}
	if err := systemdReload(); err != nil {
		cleanup()
		return "", "", err
	}
	out, err := exec.Command("systemctl", "enable", "--now", service).CombinedOutput()
	if err != nil {
		journal := xrayOpenVPNJournal(service)
		cleanup()
		return "", "", fmt.Errorf("start OpenVPN Xray sidecar: %w: %s; journal: %s", err, tailText(string(out), 2000), journal)
	}
	if err := waitForXrayOpenVPNInbounds(service, bindings); err != nil {
		journal := xrayOpenVPNJournal(service)
		cleanup()
		return "", "", fmt.Errorf("%w; journal: %s", err, journal)
	}
	return configPath, service, nil
}
func removeXrayOpenVPNSidecar(meta *XrayOpenVPNIntegration) error {
	if meta == nil {
		return nil
	}
	unitPath, err := xrayOpenVPNUnitPath(meta.Service)
	if err != nil {
		return err
	}
	dir, err := xrayOpenVPNConfigDir(meta.ConfigPath)
	if err != nil {
		return err
	}
	out, e := exec.Command("systemctl", "disable", "--now", meta.Service).CombinedOutput()
	if e != nil {
		state, _ := exec.Command("systemctl", "show", meta.Service, "-p", "LoadState", "--value").Output()
		if strings.TrimSpace(string(state)) != "not-found" {
			return fmt.Errorf("stop Xray OpenVPN sidecar: %w: %s", e, strings.TrimSpace(string(out)))
		}
	}
	if e := os.Remove(unitPath); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := os.RemoveAll(dir); e != nil {
		return e
	}
	if e := systemdReload(); e != nil {
		return e
	}
	_ = exec.Command("systemctl", "reset-failed", meta.Service).Run()
	return nil
}

func applyXrayOpenVPNEgress() error {
	if !isRoot() {
		return errors.New("run the manager as root to safely create the dedicated OpenVPN Xray service")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" {
		return errors.New("OpenVPN user egress can only be applied to an Agent profile")
	}
	if cfg.OpenVPNConfig == "" || cfg.OpenVPNService == "" {
		return errors.New("no managed OpenVPN profile is configured")
	}
	if cfg.XrayWARP != nil || cfg.XrayPsiphon != nil || cfg.XrayOpenVPN != nil {
		return errors.New("this Agent already has an isolated Xray egress integration")
	}
	if err := verifyOpenVPNRoute(&cfg); err != nil {
		return err
	}
	exitIP, err := openVPNPublicEgressIP(cfg.OpenVPNMark, 15*time.Second)
	if err != nil {
		return err
	}
	uiSuccess("Verified isolated OpenVPN egress IP: " + exitIP)
	oldProfile, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var runtime xrayRuntime
	for i, m := range cfg.Ports {
		_, p, e := net.SplitHostPort(m.Target)
		if e != nil {
			return fmt.Errorf("mapping %q target must be IP:PORT: %w", m.ID, e)
		}
		port, e := strconv.Atoi(p)
		if e != nil || port < 1 || port > 65535 {
			return fmt.Errorf("mapping %q target port is invalid", m.ID)
		}
		rt, _, e := findXrayRuntimeForPort(port)
		if e != nil {
			return fmt.Errorf("detect Xray for mapping %q: %w", m.ID, e)
		}
		if i == 0 {
			runtime = rt
		} else if filepath.Clean(runtime.ConfigPath) != filepath.Clean(rt.ConfigPath) || runtime.Binary != rt.Binary || runtime.CWD != rt.CWD {
			return errors.New("all OpenVPN-routed mappings in one tunnel must belong to the same Xray instance")
		}
	}
	original, err := os.ReadFile(runtime.ConfigPath)
	if err != nil {
		return fmt.Errorf("read Xray source config: %w", err)
	}
	profile := strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
	generated, bindings, outTag, err := buildXrayOpenVPNConfig(original, profile, cfg.OpenVPNMark, cfg.Ports)
	if err != nil {
		return err
	}
	stateDir := xrayOpenVPNDir(profile)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	tf, err := os.CreateTemp(stateDir, ".config-test-*.json")
	if err != nil {
		return err
	}
	testPath := tf.Name()
	if _, err = tf.Write(generated); err != nil {
		_ = tf.Close()
		_ = os.Remove(testPath)
		return err
	}
	_ = tf.Chmod(0600)
	if err = tf.Close(); err != nil {
		_ = os.Remove(testPath)
		return err
	}
	defer os.Remove(testPath)
	if err := validateXrayConfig(runtime, testPath); err != nil {
		return fmt.Errorf("Xray rejected OpenVPN sidecar config: %w", err)
	}
	sidecarConfig, sidecarService, err := installXrayOpenVPNSidecar(runtime, profile, generated, bindings, cfg.OpenVPNService)
	if err != nil {
		return err
	}
	rollback := func() {
		_ = removeXrayOpenVPNSidecar(&XrayOpenVPNIntegration{ConfigPath: sidecarConfig, Service: sidecarService})
	}
	byID := make(map[string]XrayOpenVPNBinding, len(bindings))
	for _, b := range bindings {
		byID[b.MappingID] = b
	}
	for i := range cfg.Ports {
		b, ok := byID[cfg.Ports[i].ID]
		if !ok {
			rollback()
			return fmt.Errorf("no OpenVPN Xray binding for mapping %q", cfg.Ports[i].ID)
		}
		cfg.Ports[i].Target = b.OpenVPNTarget
	}
	cfg.XrayOpenVPN = &XrayOpenVPNIntegration{ConfigPath: sidecarConfig, Service: sidecarService, OutboundTag: outTag, Mark: cfg.OpenVPNMark, Bindings: bindings}
	if err := saveConfig(cfg); err != nil {
		_ = atomicReplaceFile(configPath, oldProfile, 0600)
		rollback()
		return fmt.Errorf("save OpenVPN-only mapping targets: %w", err)
	}
	uiSuccess("Per-profile Xray TCP/UDP and DNS egress now uses the isolated OpenVPN policy route.")
	uiInfo("The X-UI source config, host default route, SSH and unrelated tunnel profiles were not modified.")
	return nil
}
func removeXrayOpenVPNIntegration(cfg *Config) error {
	if cfg == nil || cfg.XrayOpenVPN == nil {
		return nil
	}
	meta := cfg.XrayOpenVPN
	if err := removeXrayOpenVPNSidecar(meta); err != nil {
		return fmt.Errorf("remove dedicated OpenVPN Xray service: %w", err)
	}
	for i := range cfg.Ports {
		for _, b := range meta.Bindings {
			if cfg.Ports[i].ID == b.MappingID {
				cfg.Ports[i].Target = b.OriginalTarget
			}
		}
	}
	cfg.XrayOpenVPN = nil
	return nil
}
func autoApplyXrayOpenVPNForNewAgent() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Role != "agent" || cfg.OpenVPNConfig == "" || cfg.XrayOpenVPN != nil {
		return nil
	}
	uiInfo("Preparing an isolated Xray sidecar whose marked sockets use this Agent's OpenVPN TUN policy table…")
	if err := applyXrayOpenVPNEgress(); err != nil {
		// Do not leave a half-created Agent profile behind. The Xray installer
		// rolls back its sidecar transaction; now remove the managed OpenVPN
		// service, policy rules, credentials and per-profile capability drop-in.
		fresh, loadErr := loadConfig()
		if loadErr != nil {
			return fmt.Errorf("automatic per-profile OpenVPN egress setup failed: %w (could not reload profile for rollback: %v)", err, loadErr)
		}
		if cleanupErr := removeOpenVPNProfile(&fresh); cleanupErr != nil {
			return fmt.Errorf("automatic per-profile OpenVPN egress setup failed: %w (OpenVPN rollback also failed: %v)", err, cleanupErr)
		}
		fresh.OpenVPNConfig = ""
		fresh.OpenVPNAuthFile = ""
		fresh.OpenVPNService = ""
		fresh.OpenVPNDevice = ""
		fresh.OpenVPNTable = 0
		fresh.OpenVPNMark = 0
		fresh.OpenVPNPriority = 0
		if saveErr := saveConfig(fresh); saveErr != nil {
			return fmt.Errorf("automatic per-profile OpenVPN egress setup failed: %w (cleaned service, but could not clear profile metadata: %v)", err, saveErr)
		}
		return fmt.Errorf("automatic per-profile OpenVPN egress setup failed and was rolled back cleanly: %w", err)
	}
	return nil
}
