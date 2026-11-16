package main

import (
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
# Managed-By: ShahTunnel 5.0.0
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

// xrayPsiphonUnitBelongsToProfile recognizes only the exact service/config pair
// ShahTunnel creates for this profile. This permits safe repair after an
// interrupted first setup without taking over a similarly named third-party
// unit or another profile's configuration.
func xrayPsiphonUnitBelongsToProfile(unit []byte, runtime xrayRuntime, configPath, service string) bool {
	if len(unit) == 0 || runtime.Binary == "" || runtime.CWD == "" || filepath.Base(service) != service ||
		!strings.HasPrefix(service, "shah-tunnel-xray-psiphon-") || !strings.HasSuffix(service, ".service") {
		return false
	}
	text := string(unit)
	if !strings.Contains(text, "Description=ShahTunnel isolated Psiphon Xray (") {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		// The Xray binary may have moved during an upgrade. Ownership is tied
		// to the ShahTunnel unit description and its exact profile config path;
		// the replacement unit will use the currently detected binary.
		if strings.HasPrefix(line, "ExecStart=") && strings.HasSuffix(line, " run -config "+systemdExecQuote(configPath)) {
			return true
		}
	}
	return false
}

func restoreXrayPsiphonSidecar(service, unitPath, configPath string, oldUnit, oldConfig []byte, hadConfig, wasActive, wasEnabled bool) error {
	_ = exec.Command("systemctl", "stop", service).Run()
	var restoreErr error
	if err := atomicReplaceFile(unitPath, oldUnit, 0644); err != nil {
		restoreErr = errors.Join(restoreErr, fmt.Errorf("restore prior unit: %w", err))
	}
	if hadConfig {
		if err := atomicReplaceFile(configPath, oldConfig, 0600); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore prior Xray config: %w", err))
		}
	} else if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		restoreErr = errors.Join(restoreErr, fmt.Errorf("remove replacement Xray config: %w", err))
	}
	if err := systemdReload(); err != nil {
		restoreErr = errors.Join(restoreErr, err)
	}
	if wasEnabled {
		if out, err := exec.Command("systemctl", "enable", service).CombinedOutput(); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore enabled state: %w: %s", err, strings.TrimSpace(string(out))))
		}
	} else {
		if out, err := exec.Command("systemctl", "disable", service).CombinedOutput(); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore disabled state: %w: %s", err, strings.TrimSpace(string(out))))
		}
	}
	if wasActive {
		if out, err := exec.Command("systemctl", "start", service).CombinedOutput(); err != nil {
			restoreErr = errors.Join(restoreErr, fmt.Errorf("restore active state: %w: %s", err, strings.TrimSpace(string(out))))
		}
	}
	return restoreErr
}

func installXrayPsiphonSidecar(runtime xrayRuntime, profileID string, generated []byte, bindings []XrayPsiphonBinding) (string, string, error) {
	service := xrayPsiphonServiceName(profileID)
	unitPath, err := xrayPsiphonUnitPath(service)
	if err != nil {
		return "", "", err
	}
	configDir := xrayPsiphonDirectory(profileID)
	configPath := filepath.Join(configDir, "config.json")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", "", err
	}
	if err := os.Chmod(configDir, 0700); err != nil {
		return "", "", err
	}
	dirInfo, err := os.Lstat(configDir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		if err != nil {
			return "", "", fmt.Errorf("inspect profile-local Psiphon Xray directory: %w", err)
		}
		return "", "", fmt.Errorf("profile-local Psiphon Xray path %s is not a real directory", configDir)
	}
	if configInfo, configStatErr := os.Lstat(configPath); configStatErr == nil {
		if !configInfo.Mode().IsRegular() {
			return "", "", fmt.Errorf("profile-local Psiphon Xray config %s is not a regular file; refusing to replace it", configPath)
		}
	} else if !errors.Is(configStatErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("inspect profile-local Psiphon Xray config: %w", configStatErr)
	}
	unit, err := renderXrayPsiphonUnit(runtime, configPath, service)
	if err != nil {
		return "", "", err
	}

	// First-time setup may have been interrupted after systemd installed the
	// sidecar unit but before the profile metadata was committed. Adopt and
	// update only the exact ShahTunnel unit for this profile; never overwrite an
	// unknown unit, symlink, or unit pointing outside this profile directory.
	st, statErr := os.Lstat(unitPath)
	if statErr == nil {
		if !st.Mode().IsRegular() {
			return "", "", fmt.Errorf("managed Psiphon Xray unit path %s is not a regular file; refusing to replace it", unitPath)
		}
		oldUnit, readErr := os.ReadFile(unitPath)
		if readErr != nil {
			return "", "", fmt.Errorf("read existing Psiphon Xray unit %s: %w", service, readErr)
		}
		if !xrayPsiphonUnitBelongsToProfile(oldUnit, runtime, configPath, service) {
			return "", "", fmt.Errorf("unit %s already exists but is not the ShahTunnel sidecar for this profile; refusing to overwrite it", service)
		}
		if err := systemdReload(); err != nil {
			return "", "", fmt.Errorf("reload existing managed Psiphon Xray unit before repair: %w", err)
		}
		oldConfig, configErr := os.ReadFile(configPath)
		hadConfig := configErr == nil
		if configErr != nil && !errors.Is(configErr, os.ErrNotExist) {
			return "", "", fmt.Errorf("read existing Psiphon Xray config: %w", configErr)
		}
		wasActive := exec.Command("systemctl", "is-active", "--quiet", service).Run() == nil
		wasEnabled := exec.Command("systemctl", "is-enabled", "--quiet", service).Run() == nil
		if out, stopErr := exec.Command("systemctl", "stop", service).CombinedOutput(); stopErr != nil {
			return "", "", fmt.Errorf("stop previous managed sidecar %s before repair: %w: %s", service, stopErr, strings.TrimSpace(string(out)))
		}
		rollback := func(cause error) (string, string, error) {
			restoreErr := restoreXrayPsiphonSidecar(service, unitPath, configPath, oldUnit, oldConfig, hadConfig, wasActive, wasEnabled)
			if restoreErr != nil {
				return "", "", fmt.Errorf("%w; previous sidecar restoration also failed: %v", cause, restoreErr)
			}
			return "", "", cause
		}
		if err := atomicReplaceFile(configPath, generated, 0600); err != nil {
			return rollback(fmt.Errorf("replace isolated Psiphon Xray config: %w", err))
		}
		if err := atomicReplaceFile(unitPath, unit, 0644); err != nil {
			return rollback(fmt.Errorf("replace isolated Psiphon Xray unit: %w", err))
		}
		if err := systemdReload(); err != nil {
			return rollback(err)
		}
		out, startErr := exec.Command("systemctl", "enable", "--now", service).CombinedOutput()
		if startErr != nil {
			journal := xrayPsiphonJournal(service)
			return rollback(fmt.Errorf("start repaired isolated Xray service %s: %w: %s; journal: %s", service, startErr, strings.TrimSpace(string(out)), journal))
		}
		if err := waitForXrayPsiphonInbounds(service, bindings); err != nil {
			journal := xrayPsiphonJournal(service)
			return rollback(fmt.Errorf("repaired sidecar did not expose all loopback inbounds: %w; journal: %s", err, journal))
		}
		return configPath, service, nil
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("inspect Psiphon Xray unit path: %w", statErr)
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
	if err := atomicReplaceFile(unitPath, unit, 0644); err != nil {
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

// xrayPsiphonUnitBelongsToConfig validates a sidecar using only the saved
// profile metadata. It is used for lifecycle operations where Xray itself may
// not yet be running, so runtime discovery is intentionally unnecessary.
func xrayPsiphonUnitBelongsToConfig(unit []byte, cfg Config) bool {
	if cfg.XrayPsiphon == nil || cfg.Name == "" || len(cfg.XrayPsiphon.Bindings) == 0 {
		return false
	}
	meta := cfg.XrayPsiphon
	expectedService := xrayPsiphonServiceName(cfg.Name)
	expectedConfig := filepath.Join(xrayPsiphonDirectory(cfg.Name), "config.json")
	if meta.Service != expectedService || filepath.Clean(meta.ConfigPath) != filepath.Clean(expectedConfig) ||
		!isLoopbackProxyAddress(meta.Proxy) || strings.TrimSpace(meta.Proxy) != strings.TrimSpace(cfg.PsiphonProxy) {
		return false
	}
	text := string(unit)
	if !strings.Contains(text, "Description=ShahTunnel isolated Psiphon Xray (") {
		return false
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ExecStart=") && strings.HasSuffix(line, " run -config "+systemdExecQuote(expectedConfig)) {
			return true
		}
	}
	return false
}

// ensureXrayPsiphonSidecar starts a previously-created profile-local Xray
// sidecar before Agent startup. It never adopts a unit that does not point to
// this exact profile config.
func ensureXrayPsiphonSidecar(cfg Config) error {
	if cfg.XrayPsiphon == nil {
		return nil
	}
	meta := cfg.XrayPsiphon
	unitPath, err := xrayPsiphonUnitPath(meta.Service)
	if err != nil {
		return err
	}
	st, err := os.Lstat(unitPath)
	if err != nil {
		return fmt.Errorf("inspect profile Psiphon Xray unit: %w", err)
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("profile Psiphon Xray unit %s is not a regular file", meta.Service)
	}
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		return err
	}
	if !xrayPsiphonUnitBelongsToConfig(unit, cfg) {
		return fmt.Errorf("profile Psiphon Xray unit %s does not match saved profile metadata", meta.Service)
	}
	if err := systemdReload(); err != nil {
		return err
	}
	out, err := exec.Command("systemctl", "enable", "--now", meta.Service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("start profile Psiphon Xray sidecar %s: %w: %s; journal: %s", meta.Service, err, strings.TrimSpace(string(out)), xrayPsiphonJournal(meta.Service))
	}
	if err := waitForXrayPsiphonInbounds(meta.Service, meta.Bindings); err != nil {
		return err
	}
	return nil
}

// stopXrayPsiphonSidecar stops, but does not disable, the selected profile's
// sidecar. A later Agent Start re-enables/starts it before the Agent service.
func stopXrayPsiphonSidecar(cfg Config) error {
	if cfg.XrayPsiphon == nil {
		return nil
	}
	meta := cfg.XrayPsiphon
	unitPath, err := xrayPsiphonUnitPath(meta.Service)
	if err != nil {
		return err
	}
	st, err := os.Lstat(unitPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("profile Psiphon Xray unit %s is not a regular file; refusing to stop it", meta.Service)
	}
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		return err
	}
	if !xrayPsiphonUnitBelongsToConfig(unit, cfg) {
		return fmt.Errorf("profile Psiphon Xray unit %s does not match saved profile metadata; refusing to stop it", meta.Service)
	}
	out, err := exec.Command("systemctl", "stop", meta.Service).CombinedOutput()
	if err != nil {
		state, _ := exec.Command("systemctl", "show", meta.Service, "-p", "LoadState", "--value").Output()
		if strings.TrimSpace(string(state)) == "not-found" {
			return nil
		}
		return fmt.Errorf("stop profile Psiphon Xray sidecar %s: %w: %s", meta.Service, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// psiphonRegionCandidates returns the persisted working region first (except
// the legacy DE default), followed by the exact country order supplied by the
// user. Germany remains an allowed fallback, but is never the initial choice.
func psiphonRegionCandidates(preferred string) []string {
	preferred = strings.ToUpper(strings.TrimSpace(preferred))
	result := make([]string, 0, len(psiphonEgressRegionPriority))
	seen := make(map[string]bool, len(psiphonEgressRegionPriority))
	if preferred != "" && preferred != "DE" && psiphonAllowedEgressRegions[preferred] {
		result = append(result, preferred)
		seen[preferred] = true
	}
	for _, region := range psiphonEgressRegionPriority {
		if !seen[region] {
			result = append(result, region)
			seen[region] = true
		}
	}
	return result
}

func readPsiphonPreferredRegion(configPath string) string {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	var cfg psiphonClientConfig
	if json.Unmarshal(data, &cfg) != nil {
		return ""
	}
	region, _ := normalizePsiphonEgressRegion(cfg.EgressRegion)
	return region
}

func psiphonExitMatchesVPSDirectIP(exitIP, directIP string) bool {
	exit := net.ParseIP(strings.TrimSpace(exitIP))
	direct := net.ParseIP(strings.TrimSpace(directIP))
	return exit != nil && direct != nil && exit.To4() != nil && direct.To4() != nil && exit.To4().Equal(direct.To4())
}

func verifyPsiphonExit(proxy, expectedRegion, directIP string) (string, string, error) {
	ip, err := waitForPsiphonPublicEgressIP(proxy, 8*time.Second)
	if err != nil {
		return "", "", err
	}
	if psiphonExitMatchesVPSDirectIP(ip, directIP) {
		return "", "", fmt.Errorf("SOCKS5 returned the VPS direct public IP %s; refusing this as a Psiphon exit", ip)
	}
	country, geoErr := psiphonPublicEgressCountry(proxy, ip, 5*time.Second)
	if geoErr != nil {
		country, geoErr = psiphonCountryFromDirectIPLookup(ip)
	}
	if geoErr != nil {
		return "", "", fmt.Errorf("cannot verify country for Psiphon exit %s: %w", ip, geoErr)
	}
	if country != expectedRegion {
		return "", "", fmt.Errorf("requested country %s but Psiphon returned %s (%s)", expectedRegion, country, ip)
	}
	if country == "US" || !psiphonAllowedEgressRegions[country] {
		return "", "", fmt.Errorf("Psiphon exit %s (%s) is not in the approved country list", ip, country)
	}
	return ip, country, nil
}

// selectPsiphonExitByPriority enforces the ordered country list instead of
// relying on Psiphon's unrestricted empty-region auto-selection. It also
// compares the SOCKS exit with the VPS's independently discovered direct IP;
// an identical address is rejected and is never exposed to Xray users.
func selectPsiphonExitByPriority(cfg Config) (string, string, error) {
	proxy := strings.TrimSpace(cfg.PsiphonProxy)
	configPath := strings.TrimSpace(cfg.PsiphonConfig)
	if !isLoopbackProxyAddress(proxy) || configPath == "" {
		return "", "", errors.New("Psiphon profile is missing a valid loopback proxy or config path")
	}
	// This transport explicitly disables HTTP proxy environment variables, so
	// the value is the VPS's ordinary public egress address, not Psiphon.
	directIP := detectPublicIPv4FromAPIs()
	if directIP == "" {
		if cached := readServerGeoCache(); cached.Valid {
			directIP = cached.IP
		}
	}
	if directIP == "" {
		return "", "", errors.New("cannot establish the VPS direct public IP baseline; refusing to enable Psiphon user egress without leak detection")
	}
	service := psiphonServiceName(cfg.Name)
	preferred := readPsiphonPreferredRegion(configPath)
	candidates := psiphonRegionCandidates(preferred)
	var failures []string
	for index, region := range candidates {
		log.Printf("Psiphon country selection: trying %s (%d/%d)", region, index+1, len(candidates))
		changed, err := setPsiphonEgressRegionPreference(configPath, region)
		if err != nil {
			return "", "", err
		}
		// A matching live process is probed first to preserve warm tunnels. If
		// the preference changes, restart only this profile to apply the region.
		if changed || index > 0 {
			if err := runSystemctl("restart", service); err != nil {
				failures = append(failures, region+": restart failed: "+err.Error())
				continue
			}
		}
		if ip, country, probeErr := verifyPsiphonExit(proxy, region, directIP); probeErr == nil {
			log.Printf("Psiphon selected preferred exit: country=%s ip=%s direct_vps_ip=%s", country, ip, directIP)
			return ip, country, nil
		} else {
			log.Printf("Psiphon country %s was not verified: %v; trying the next requested country", region, probeErr)
			failures = append(failures, region+": "+probeErr.Error())
		}
	}
	return "", "", fmt.Errorf("no Psiphon exit was verified in the requested country order (%s); Xray user traffic remains fail-closed", strings.Join(failures, " | "))
}

// ensurePsiphonUserEgressReady also verifies that every saved Agent mapping
// points to the profile's isolated Xray sidecar, never the original Xray port.
func validatePsiphonMappingTargets(cfg Config) error {
	if cfg.XrayPsiphon == nil {
		return errors.New("profile has no isolated Psiphon Xray integration")
	}
	bindings := make(map[string]XrayPsiphonBinding, len(cfg.XrayPsiphon.Bindings))
	for _, binding := range cfg.XrayPsiphon.Bindings {
		if binding.MappingID == "" || binding.PsiphonTarget == "" || binding.OriginalTarget == "" {
			return errors.New("Psiphon Xray integration contains an incomplete mapping binding")
		}
		bindings[binding.MappingID] = binding
	}
	for _, mapping := range cfg.Ports {
		binding, ok := bindings[mapping.ID]
		if !ok || mapping.Target != binding.PsiphonTarget || mapping.Target == binding.OriginalTarget {
			return fmt.Errorf("mapping %s is not pointed at its isolated Psiphon Xray inbound; refusing possible direct-IP fallback", mapping.ID)
		}
	}
	return nil
}

func ensurePsiphonUserEgressReady(cfg Config) error {
	if cfg.XrayPsiphon == nil {
		return nil
	}
	proxy := strings.TrimSpace(cfg.XrayPsiphon.Proxy)
	if !isLoopbackProxyAddress(proxy) || proxy != strings.TrimSpace(cfg.PsiphonProxy) {
		return errors.New("saved Xray Psiphon route does not match the profile's loopback SOCKS5 endpoint")
	}
	if err := validatePsiphonMappingTargets(cfg); err != nil {
		return err
	}
	ip, country, err := selectPsiphonExitByPriority(cfg)
	if err != nil {
		return fmt.Errorf("Psiphon user egress is not ready; Xray remains gated: %w", err)
	}
	log.Printf("Psiphon user egress verified: %s (%s); Agent direct IP is excluded", ip, country)
	return nil
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
	// Select an actual exit by the user's ordered country list and reject the
	// VPS's own direct IP before creating or exposing the Xray user route.
	ip, country, err := selectPsiphonExitByPriority(cfg)
	if err != nil {
		return err
	}
	uiSuccess(fmt.Sprintf("Verified Psiphon exit in requested country: %s (country %s)", ip, country))
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
		// Verify the actual selected-country proxy exit again after Agent restart,
		// and assert every saved mapping still targets the isolated sidecar.
		if err = ensurePsiphonUserEgressReady(cfg); err != nil {
			_ = atomicReplaceFile(configPath, oldProfile, 0600)
			_ = runSystemctl("restart", service)
			rollbackSidecar()
			return fmt.Errorf("Psiphon user-egress verification failed after Agent restart; previous profile was restored: %w", err)
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
	if err := ensurePsiphonSystemdService(cfg); err != nil {
		return fmt.Errorf("prepare the profile-local Psiphon service before Xray setup: %w", err)
	}
	if err := applyXrayPsiphonEgress(false, false); err != nil {
		return fmt.Errorf("Agent profile was saved, but automatic per-tunnel Psiphon user-egress setup failed: %w", err)
	}
	return nil
}
