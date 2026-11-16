package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	psiphonConsoleClientPath = "/usr/local/bin/psiphon-console-client"
	psiphonInstallerPath     = "/usr/local/lib/shah-tunnel/install-psiphon.sh"
	psiphonConfigDir         = "/etc/ravanreverse/psiphon"
	psiphonDataRoot          = "/var/lib/shah-tunnel/psiphon"

	// Public Psiphon 3 bootstrap values extracted from the public Android client.
	// Repeating F/0 identifiers are placeholders and cannot authenticate the
	// public server-list bootstrap.
	psiphonPropagationChannelID    = "92AACC5BABE0944C"
	psiphonSponsorID               = "1BC527D3D09985CF"
	psiphonRemoteServerListURL     = "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	psiphonRemoteServerListKey     = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
	psiphonServerEntrySignatureKey = "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA="
	psiphonExchangeObfuscationKey  = "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU="
)

var (
	psiphonRemoteServerListMirrors = []string{
		psiphonRemoteServerListURL,
		"https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/server_list_compressed",
		"https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/server_list_compressed",
		"https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/server_list_compressed",
	}
	psiphonObfuscatedServerListRoots = []string{
		"https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/osl",
		"https://www.blogsfmcancercitizen.com/web/mjr4-p23r-puwl/osl",
		"https://www.herbxdiiincorporated.com/web/mjr4-p23r-puwl/osl",
		"https://www.xydiamonddbexpert.com/web/mjr4-p23r-puwl/osl",
	}
)

// Psiphon TransferURL fields use base64-encoded URL strings. The public
// bootstrap requires at least one entry with OnlyAfterAttempts=0.
type psiphonTransferURL struct {
	URL               string `json:"URL"`
	OnlyAfterAttempts int    `json:"OnlyAfterAttempts"`
	SkipVerify        bool   `json:"SkipVerify"`
}

// psiphonClientConfig is intentionally limited to ConsoleClient's SOCKS mode.
// No TUN device or host routing is configured by ShahTunnel.
type psiphonClientConfig struct {
	ClientVersion                      string               `json:"ClientVersion"`
	ClientPlatform                     string               `json:"ClientPlatform"`
	PropagationChannelID               string               `json:"PropagationChannelId"`
	SponsorID                          string               `json:"SponsorId"`
	EgressRegion                       string               `json:"EgressRegion"`
	LocalSocksProxyPort                int                  `json:"LocalSocksProxyPort"`
	DisableLocalSocksProxy             bool                 `json:"DisableLocalSocksProxy,omitempty"`
	DisableLocalHTTPProxy              bool                 `json:"DisableLocalHTTPProxy"`
	UseUnixDomainSockets               bool                 `json:"UseUnixDomainSockets"`
	TargetServerEntry                  string               `json:"TargetServerEntry,omitempty"`
	RemoteServerListDownloadFilename   string               `json:"RemoteServerListDownloadFilename"`
	RemoteServerListURLs               []psiphonTransferURL `json:"RemoteServerListURLs"`
	RemoteServerListSignaturePublicKey string               `json:"RemoteServerListSignaturePublicKey"`
	ObfuscatedServerListRootURLs       []psiphonTransferURL `json:"ObfuscatedServerListRootURLs"`
	ServerEntrySignaturePublicKey      string               `json:"ServerEntrySignaturePublicKey"`
	ExchangeObfuscationKey             string               `json:"ExchangeObfuscationKey"`
	// Kept for compatibility with the currently deployed ShahTunnel binary;
	// Psiphon prefers the plural TransferURLs field when it is present.
	RemoteServerListURL         string `json:"RemoteServerListUrl,omitempty"`
	UseIndistinguishableTLS     bool   `json:"UseIndistinguishableTLS"`
	LimitMeekBufferSizes        bool   `json:"LimitMeekBufferSizes"`
	LimitCPUThreads             bool   `json:"LimitCPUThreads"`
	LimitRelayBufferSizes       bool   `json:"LimitRelayBufferSizes"`
	SSHChannelWindowSize        *int   `json:"SSHChannelWindowSize,omitempty"`
	ConnectionWorkerPoolMaxSize int    `json:"ConnectionWorkerPoolMaxSize,omitempty"`
	// TunnelPoolSize is the number of independent Psiphon tunnels carrying
	// multiplexed port-forward streams. Upstream defaults to one.
	TunnelPoolSize        int  `json:"TunnelPoolSize,omitempty"`
	EmitDiagnosticNotices bool `json:"EmitDiagnosticNotices,omitempty"`
}

// psiphonConsoleClientArgs deliberately leaves ListenInterface unset so the
// local SOCKS proxy uses Psiphon's built-in loopback binding. Psiphon's WebRTC
// ICE/in-proxy stack may still enumerate host interfaces through AF_NETLINK;
// the Agent systemd unit allows that socket family while retaining the narrow
// capability set (no CAP_NET_ADMIN), so no route or interface is modified.
func psiphonConsoleClientArgs(configPath, dataDir string) []string {
	return []string{"-config", configPath, "-dataRootDirectory", dataDir}
}

type psiphonPerformanceProfile struct {
	LimitMeekBufferSizes  bool
	LimitCPUThreads       bool
	LimitRelayBufferSizes bool
	SSHChannelWindowSize  int
	TunnelPoolSize        int
}

const psiphonHighThroughputMinRAM = uint64(3 << 30) // 3 GiB

// psiphonPerformanceProfileForHost avoids oversized buffers on small VPSes,
// but removes Psiphon's conservative relay/Meek buffer caps when the host has
// enough memory. CPU thread limiting is disabled only on multi-core hosts.
func intPointer(value int) *int {
	return &value
}

func psiphonPerformanceProfileForHost(totalRAMBytes uint64, cpuCount int) psiphonPerformanceProfile {
	lowMemory := totalRAMBytes < psiphonHighThroughputMinRAM
	windowSize := 16
	if lowMemory {
		// Psiphon documents 4 as the default SSH channel window (128 KiB).
		// Keep that conservative default on small hosts; a moderate 16-packet
		// window (512 KiB) improves throughput on high-RTT paths when RAM allows.
		windowSize = 4
	}
	// Psiphon's upstream TunnelPoolSize defaults to one. Scale conservatively
	// with RAM and CPU so a single SOCKS endpoint is not forced through one
	// long-lived Psiphon tunnel. This does not manufacture bandwidth; it exposes
	// independent relays when the Psiphon network and VPS have capacity.
	tunnelPoolSize := 2
	if cpuCount >= 2 && totalRAMBytes >= 2<<30 {
		tunnelPoolSize = 4
	}
	if cpuCount >= 2 && totalRAMBytes >= 4<<30 {
		tunnelPoolSize = 8
	}
	if cpuCount >= 4 && totalRAMBytes >= 8<<30 {
		tunnelPoolSize = 12
	}
	if cpuCount >= 8 && totalRAMBytes >= 16<<30 {
		tunnelPoolSize = 16
	}
	return psiphonPerformanceProfile{
		LimitMeekBufferSizes:  lowMemory,
		LimitCPUThreads:       cpuCount < 2,
		LimitRelayBufferSizes: lowMemory,
		SSHChannelWindowSize:  windowSize,
		TunnelPoolSize:        tunnelPoolSize,
	}
}

func psiphonHostPerformanceProfile() psiphonPerformanceProfile {
	// Fail safe: if memory information cannot be read, preserve conservative
	// buffer limits rather than risking memory pressure on an unknown VPS.
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return psiphonPerformanceProfileForHost(0, runtime.NumCPU())
	}
	var totalRAM uint64
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if kib, parseErr := strconv.ParseUint(fields[1], 10, 64); parseErr == nil {
				totalRAM = kib * 1024
			}
		}
		break
	}
	return psiphonPerformanceProfileForHost(totalRAM, runtime.NumCPU())
}

// Psiphon region preferences intentionally exclude the United States.
// A requested region is only a preference; the live exit country is verified
// independently before Xray user egress is enabled.
// The ordered region list is the approved candidate order. Psiphon accepts
// one EgressRegion per ConsoleClient instance; DE is the initial preference,
// while the complete list is used to validate permitted exit countries. The
// actual country is always verified because availability is network-dependent.
var psiphonEgressRegionPriority = []string{
	// Priority 1: nearer alternatives to Iran.
	"DE", "TR", "AE", "RS", "RO", "BG", "GR", "GE", "AM", "AZ",
	// Priority 2: secondary alternatives.
	"NL", "CH", "AT", "PL", "CZ", "SK", "HU", "FR", "SE", "FI",
}

var psiphonAllowedEgressRegions = func() map[string]bool {
	allowed := make(map[string]bool, len(psiphonEgressRegionPriority))
	for _, region := range psiphonEgressRegionPriority {
		allowed[region] = true
	}
	return allowed
}()

func normalizePsiphonEgressRegion(region string) (string, error) {
	region = strings.ToUpper(strings.TrimSpace(region))
	if region == "" {
		return "DE", nil
	}
	if region == "US" || !psiphonAllowedEgressRegions[region] {
		return "", fmt.Errorf("Psiphon egress region %q is blocked or not in the approved non-US region list", region)
	}
	return region, nil
}

func newPsiphonClientConfig(port int) psiphonClientConfig {
	performance := psiphonHostPerformanceProfile()
	return psiphonClientConfig{
		ClientVersion:                      "1",
		ClientPlatform:                     "Linux",
		PropagationChannelID:               psiphonPropagationChannelID,
		SponsorID:                          psiphonSponsorID,
		EgressRegion:                       "DE",
		LocalSocksProxyPort:                port,
		DisableLocalHTTPProxy:              true,
		UseUnixDomainSockets:               false,
		RemoteServerListDownloadFilename:   "remote_server_list",
		RemoteServerListURLs:               makePsiphonTransferURLs(psiphonRemoteServerListMirrors),
		RemoteServerListSignaturePublicKey: psiphonRemoteServerListKey,
		ObfuscatedServerListRootURLs:       makePsiphonTransferURLs(psiphonObfuscatedServerListRoots),
		ServerEntrySignaturePublicKey:      psiphonServerEntrySignatureKey,
		ExchangeObfuscationKey:             psiphonExchangeObfuscationKey,
		// Retain the legacy scalar URL for compatibility with existing
		// ShahTunnel binaries during an in-place config-only recovery.
		RemoteServerListURL:     psiphonRemoteServerListURL,
		UseIndistinguishableTLS: true,
		LimitMeekBufferSizes:    performance.LimitMeekBufferSizes,
		LimitCPUThreads:         performance.LimitCPUThreads,
		LimitRelayBufferSizes:   performance.LimitRelayBufferSizes,
		SSHChannelWindowSize:    intPointer(performance.SSHChannelWindowSize),
		TunnelPoolSize:          performance.TunnelPoolSize,
		// Diagnostic notices are written only to the local systemd journal;
		// they are needed to distinguish bootstrap-list failures from blocked
		// Psiphon server connections when the first tunnel is delayed.
		EmitDiagnosticNotices: true,
	}
}

func makePsiphonTransferURLs(urls []string) []psiphonTransferURL {
	out := make([]psiphonTransferURL, 0, len(urls))
	for _, raw := range urls {
		out = append(out, psiphonTransferURL{
			URL:               base64.StdEncoding.EncodeToString([]byte(raw)),
			OnlyAfterAttempts: 0,
			SkipVerify:        false,
		})
	}
	return out
}

func psiphonServiceName(profileName string) string {
	if strings.TrimSpace(profileName) == "" {
		profileName = "legacy-agent"
	}
	return "shah-tunnel-psiphon-" + tunnelID(profileName) + ".service"
}

func psiphonServiceUnitPath(service string) (string, error) {
	if filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-psiphon-") || !strings.HasSuffix(service, ".service") {
		return "", fmt.Errorf("refusing to manage non-ShahTunnel Psiphon unit %q", service)
	}
	return filepath.Join("/etc/systemd/system", service), nil
}

func renderPsiphonServiceUnit(cfg Config, service, agentService string) ([]byte, error) {
	if filepath.Base(service) != service || !strings.HasPrefix(service, "shah-tunnel-psiphon-") || !strings.HasSuffix(service, ".service") {
		return nil, errors.New("invalid ShahTunnel Psiphon service name")
	}
	if filepath.Base(agentService) != agentService || (!strings.HasPrefix(agentService, "ravanreverse@") && agentService != "ravanreverse") {
		return nil, errors.New("invalid Agent service dependency")
	}
	configPath, err := filepath.Abs(strings.TrimSpace(cfg.PsiphonConfig))
	if err != nil || configPath == "." {
		return nil, errors.New("invalid Psiphon configuration path")
	}
	client := strings.TrimSpace(cfg.PsiphonClient)
	if client == "" {
		client = psiphonConsoleClientPath
	}
	if !filepath.IsAbs(client) {
		resolved, lookErr := exec.LookPath(client)
		if lookErr != nil {
			return nil, fmt.Errorf("Psiphon ConsoleClient %q not found: %w", client, lookErr)
		}
		client = resolved
	}
	dataDir := strings.TrimSpace(cfg.PsiphonDataDir)
	if dataDir == "" {
		dataDir = filepath.Join(psiphonDataRoot, tunnelID(cfg.Name))
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve Psiphon data directory: %w", err)
	}
	for _, value := range []string{client, configPath, dataDir, service, agentService} {
		if strings.ContainsAny(value, "\x00\n\r") {
			return nil, errors.New("Psiphon service parameters contain unsupported control characters")
		}
	}
	args := psiphonConsoleClientArgs(configPath, dataDir)
	execStart := systemdExecQuote(client)
	for _, arg := range args {
		execStart += " " + systemdExecQuote(arg)
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel per-profile Psiphon ConsoleClient (%s)
After=network-online.target
Wants=network-online.target
PartOf=%s.service

[Service]
Type=simple
User=root
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=5
StartLimitIntervalSec=0
LimitNOFILE=1048576
KillSignal=SIGINT
TimeoutStopSec=12
UMask=0077
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

`, strings.TrimSuffix(service, ".service"), agentService, dataDir, execStart)
	return []byte(unit), nil
}

func ensurePsiphonSystemdService(cfg Config) error {
	if cfg.Role != "agent" || (cfg.Underlay != underlayPsiphon && cfg.Underlay != underlayAdaptive) {
		return nil
	}
	if !isRoot() {
		return errors.New("starting the per-profile Psiphon service requires root")
	}
	if err := ensurePsiphonConsoleClient(); err != nil {
		return fmt.Errorf("ensure official Psiphon ConsoleClient before service start: %w", err)
	}
	if strings.TrimSpace(cfg.PsiphonConfig) == "" || !isLoopbackProxyAddress(cfg.PsiphonProxy) {
		return errors.New("Agent Psiphon profile is missing its config or loopback SOCKS5 endpoint")
	}
	configPath, err := filepath.Abs(cfg.PsiphonConfig)
	if err != nil {
		return err
	}
	if migrated, migrateErr := repairLegacyPsiphonClientConfig(configPath, cfg.PsiphonProxy); migrateErr != nil {
		return fmt.Errorf("repair Psiphon bootstrap before service start: %w", migrateErr)
	} else if migrated {
		log.Printf("Psiphon: migrated legacy bootstrap before systemd service start")
	}
	if _, tuneErr := tunePsiphonPerformanceConfig(configPath); tuneErr != nil {
		return fmt.Errorf("tune Psiphon performance before service start: %w", tuneErr)
	}
	if err := validatePsiphonClientConfig(configPath, cfg.PsiphonProxy); err != nil {
		return fmt.Errorf("validate Psiphon service config: %w", err)
	}
	dataDir := strings.TrimSpace(cfg.PsiphonDataDir)
	if dataDir == "" {
		dataDir = filepath.Join(psiphonDataRoot, tunnelID(cfg.Name))
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create Psiphon data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		return fmt.Errorf("secure Psiphon data directory: %w", err)
	}
	service := psiphonServiceName(cfg.Name)
	unitPath, err := psiphonServiceUnitPath(service)
	if err != nil {
		return err
	}
	agentService := currentServiceName()
	unit, err := renderPsiphonServiceUnit(cfg, service, agentService)
	if err != nil {
		return err
	}
	oldUnit, readErr := os.ReadFile(unitPath)
	unitChanged := readErr != nil || string(oldUnit) != string(unit)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read existing Psiphon unit: %w", readErr)
	}
	// If an older Agent process owns this SOCKS port, stop only that profile
	// before transferring supervision to the dedicated per-profile unit.
	if exec.Command("systemctl", "is-active", "--quiet", service).Run() != nil &&
		exec.Command("systemctl", "is-active", "--quiet", agentService).Run() == nil {
		if err := runSystemctl("stop", agentService); err != nil {
			return fmt.Errorf("stop selected Agent while migrating Psiphon supervision: %w", err)
		}
	}
	if unitChanged {
		if err := atomicReplaceFile(unitPath, unit, 0644); err != nil {
			return fmt.Errorf("write per-profile Psiphon systemd unit: %w", err)
		}
	}
	// Make Agent startup depend on the independently supervised Psiphon unit.
	dropInDir := filepath.Join("/etc/systemd/system", agentService+".service.d")
	if err := os.MkdirAll(dropInDir, 0755); err != nil {
		return fmt.Errorf("create Agent Psiphon dependency drop-in: %w", err)
	}
	dropIn := []byte(fmt.Sprintf("[Unit]\nRequires=%s\nAfter=%s\n", service, service))
	if err := atomicReplaceFile(filepath.Join(dropInDir, "shah-tunnel-psiphon.conf"), dropIn, 0644); err != nil {
		return fmt.Errorf("write Agent Psiphon dependency drop-in: %w", err)
	}
	if unitChanged {
		if err := systemdReload(); err != nil {
			return err
		}
	} else {
		// The drop-in may have been added after the Psiphon unit was installed.
		if err := systemdReload(); err != nil {
			return err
		}
	}
	if exec.Command("systemctl", "is-active", "--quiet", service).Run() == nil {
		if unitChanged {
			if err := runSystemctl("restart", service); err != nil {
				return fmt.Errorf("restart updated Psiphon service: %w", err)
			}
		}
	} else if err := runSystemctl("start", service); err != nil {
		return fmt.Errorf("start per-profile Psiphon service: %w", err)
	}
	if err := waitForPsiphonProxy(cfg.PsiphonProxy, 120*time.Second); err != nil {
		journal, _ := exec.Command("journalctl", "-u", service, "-n", "50", "--no-pager", "-o", "cat").CombinedOutput()
		return fmt.Errorf("per-profile Psiphon service %s is enabled but SOCKS5 %s is not ready: %w; journal: %s", service, cfg.PsiphonProxy, err, strings.TrimSpace(string(journal)))
	}
	log.Printf("Psiphon SOCKS5 is supervised by %s and is ready at %s", service, cfg.PsiphonProxy)
	return nil
}

func ensurePsiphonConsoleClient() error {
	if os.Geteuid() != 0 {
		return errors.New("automatic Psiphon setup requires root; run the ShahTunnel manager with sudo")
	}
	if psiphonConsoleClientHealthy(psiphonConsoleClientPath) {
		return nil
	}
	if _, err := os.Stat(psiphonInstallerPath); err != nil {
		return fmt.Errorf("Psiphon auto-installer is missing at %s; rerun the ShahTunnel installer to install its helper", psiphonInstallerPath)
	}
	cmd := exec.Command("bash", psiphonInstallerPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("automatic Psiphon ConsoleClient installation failed: %w", err)
	}
	if !psiphonConsoleClientHealthy(psiphonConsoleClientPath) {
		return errors.New("Psiphon installer finished but ConsoleClient did not pass its version check")
	}
	return nil
}

func psiphonConsoleClientHealthy(binary string) bool {
	if !filepath.IsAbs(binary) {
		return false
	}
	info, err := os.Stat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return false
	}
	cmd := exec.Command(binary, "-version")
	cmd.Env = append(os.Environ(), "HOME=/root")
	output, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(strings.ToLower(string(output)), "psiphon")
}

func psiphonPortIsFree(port int) bool {
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func readUsedPsiphonPorts(configDir string) map[int]bool {
	used := make(map[int]bool)
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return used
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(configDir, entry.Name()))
		if err != nil {
			continue
		}
		var data struct {
			Port int `json:"LocalSocksProxyPort"`
		}
		if json.Unmarshal(b, &data) == nil && data.Port > 0 {
			used[data.Port] = true
		}
	}
	return used
}

func allocatePsiphonSocksPort(profileName, configDir string) (int, error) {
	if strings.TrimSpace(profileName) == "" {
		return 0, errors.New("Psiphon profile name is required")
	}
	const firstPort, portCount = 20000, 30000
	sum := sha256.Sum256([]byte(tunnelID(profileName)))
	start := int(binary.BigEndian.Uint16(sum[:2])) % portCount
	used := readUsedPsiphonPorts(configDir)
	for offset := 0; offset < portCount; offset++ {
		port := firstPort + (start+offset)%portCount
		if used[port] || !psiphonPortIsFree(port) {
			continue
		}
		return port, nil
	}
	return 0, errors.New("no free loopback port available for this Psiphon profile")
}

func writePsiphonProfileConfig(profileName string, port int, configDir string) (string, error) {
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid Psiphon SOCKS5 port: %d", port)
	}
	if strings.TrimSpace(profileName) == "" {
		return "", errors.New("Psiphon profile name is required")
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", fmt.Errorf("create Psiphon config directory: %w", err)
	}
	if err := os.Chmod(configDir, 0700); err != nil {
		return "", fmt.Errorf("secure Psiphon config directory: %w", err)
	}
	path := filepath.Join(configDir, tunnelID(profileName)+".json")
	data, err := json.MarshalIndent(newPsiphonClientConfig(port), "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(configDir, ".psiphon-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	return path, nil
}

func preparePsiphonAgentProfile(c *Config) error {
	if c == nil || c.Role != "agent" {
		return errors.New("Psiphon can only be prepared for an Agent profile")
	}
	if err := ensurePsiphonConsoleClient(); err != nil {
		return err
	}
	if err := os.MkdirAll(psiphonDataRoot, 0755); err != nil {
		return fmt.Errorf("create Psiphon data root: %w", err)
	}
	profileID := tunnelID(c.Name)
	port, err := allocatePsiphonSocksPort(c.Name, psiphonConfigDir)
	if err != nil {
		return err
	}
	configFile, err := writePsiphonProfileConfig(c.Name, port, psiphonConfigDir)
	if err != nil {
		return fmt.Errorf("write automatic Psiphon configuration: %w", err)
	}
	dataDir := filepath.Join(psiphonDataRoot, profileID)
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create Psiphon profile data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		return fmt.Errorf("secure Psiphon profile data directory: %w", err)
	}
	c.PsiphonConfig = configFile
	c.PsiphonProxy = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	c.PsiphonClient = psiphonConsoleClientPath
	c.PsiphonDataDir = dataDir
	return nil
}

// isUsablePsiphonClientID rejects missing, malformed and known placeholder IDs.
// Psiphon requires both values to be supplied by its network; the all-F values
// emitted by legacy ShahTunnel profiles are not usable client identities.
func isUsablePsiphonClientID(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 16 || strings.EqualFold(value, "FFFFFFFFFFFFFFFF") || strings.EqualFold(value, "0000000000000000") {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// psiphonBootstrapNeedsMigration recognizes the old scalar RemoteServerListUrl
// format and placeholder identities. A valid custom TargetServerEntry remains
// supported; invalid client IDs are still migrated in that case.
func psiphonBootstrapNeedsMigration(cfg psiphonClientConfig) bool {
	if !isUsablePsiphonClientID(cfg.PropagationChannelID) || !isUsablePsiphonClientID(cfg.SponsorID) {
		return true
	}
	if _, err := strconv.Atoi(strings.TrimSpace(cfg.ClientVersion)); err != nil {
		return true
	}
	if cfg.DisableLocalSocksProxy || cfg.UseUnixDomainSockets || !cfg.EmitDiagnosticNotices || cfg.ConnectionWorkerPoolMaxSize != 0 {
		return true
	}
	if cfg.TunnelPoolSize < 1 || cfg.TunnelPoolSize > 16 {
		return true
	}
	if _, err := normalizePsiphonEgressRegion(cfg.EgressRegion); err != nil {
		return true
	}
	keysIncomplete := strings.TrimSpace(cfg.RemoteServerListSignaturePublicKey) == "" ||
		strings.TrimSpace(cfg.ServerEntrySignaturePublicKey) == "" ||
		strings.TrimSpace(cfg.ExchangeObfuscationKey) == ""
	if strings.TrimSpace(cfg.TargetServerEntry) != "" {
		return keysIncomplete
	}
	return keysIncomplete || len(cfg.RemoteServerListURLs) == 0 || len(cfg.ObfuscatedServerListRootURLs) == 0
}

// repairLegacyPsiphonClientConfig upgrades incomplete legacy bootstraps from
// older ShahTunnel builds. It also recognizes the deprecated scalar URL
// layout. Valid custom identities and region preferences are preserved.
func repairLegacyPsiphonClientConfig(configPath, proxyAddress string) (bool, error) {
	if !isLoopbackProxyAddress(proxyAddress) {
		return false, errors.New("Psiphon SOCKS5 proxy must be loopback-only")
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}
	var current psiphonClientConfig
	if err := json.Unmarshal(b, &current); err != nil {
		return false, fmt.Errorf("read legacy Psiphon config: %w", err)
	}
	if !psiphonBootstrapNeedsMigration(current) {
		return false, nil
	}
	_, portText, err := net.SplitHostPort(proxyAddress)
	if err != nil {
		return false, fmt.Errorf("invalid Psiphon SOCKS5 address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || current.LocalSocksProxyPort != port {
		return false, fmt.Errorf("legacy Psiphon config port %d does not match loopback proxy %s", current.LocalSocksProxyPort, proxyAddress)
	}
	upgraded := newPsiphonClientConfig(port)
	if region, regionErr := normalizePsiphonEgressRegion(current.EgressRegion); regionErr == nil {
		upgraded.EgressRegion = region
	}
	upgraded.TargetServerEntry = current.TargetServerEntry
	if isUsablePsiphonClientID(current.PropagationChannelID) {
		upgraded.PropagationChannelID = strings.TrimSpace(current.PropagationChannelID)
	}
	if isUsablePsiphonClientID(current.SponsorID) {
		upgraded.SponsorID = strings.TrimSpace(current.SponsorID)
	}
	if strings.TrimSpace(current.ClientPlatform) != "" {
		upgraded.ClientPlatform = strings.TrimSpace(current.ClientPlatform)
	}
	if version := strings.TrimSpace(current.ClientVersion); version != "" {
		if _, parseErr := strconv.Atoi(version); parseErr == nil {
			upgraded.ClientVersion = version
		}
	}
	if strings.TrimSpace(current.RemoteServerListDownloadFilename) != "" {
		upgraded.RemoteServerListDownloadFilename = current.RemoteServerListDownloadFilename
	}
	data, err := json.MarshalIndent(upgraded, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode upgraded Psiphon config: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(configPath), ".psiphon-migrate-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create upgraded Psiphon config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, configPath); err != nil {
		return false, fmt.Errorf("replace upgraded Psiphon config: %w", err)
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		return false, err
	}
	return true, nil
}

// tunePsiphonPerformanceConfig updates only the performance settings owned by
// ShahTunnel, preserving every other field and unknown Psiphon option.
func tunePsiphonPerformanceConfig(configPath string) (bool, error) {
	return tunePsiphonPerformanceConfigForProfile(configPath, psiphonHostPerformanceProfile())
}

func tunePsiphonPerformanceConfigForProfile(configPath string, profile psiphonPerformanceProfile) (bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false, fmt.Errorf("read Psiphon performance settings: %w", err)
	}
	if raw == nil {
		return false, errors.New("Psiphon config must be a JSON object")
	}
	settings := map[string]any{
		"LimitMeekBufferSizes":  profile.LimitMeekBufferSizes,
		"LimitCPUThreads":       profile.LimitCPUThreads,
		"LimitRelayBufferSizes": profile.LimitRelayBufferSizes,
		"SSHChannelWindowSize":  profile.SSHChannelWindowSize,
		"TunnelPoolSize":        profile.TunnelPoolSize,
	}
	changed := false
	for key, value := range settings {
		encoded, _ := json.Marshal(value)
		if existing, ok := raw[key]; ok && string(existing) == string(encoded) {
			continue
		}
		raw[key] = encoded
		changed = true
	}
	if !changed {
		return false, nil
	}
	updated, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode Psiphon performance settings: %w", err)
	}
	updated = append(updated, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(configPath), ".psiphon-tune-*.tmp")
	if err != nil {
		return false, fmt.Errorf("create temporary Psiphon config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if _, err := tmp.Write(updated); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, configPath); err != nil {
		return false, fmt.Errorf("replace Psiphon config with performance profile: %w", err)
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		return false, err
	}
	return true, nil
}

func validatePsiphonClientConfig(configPath, proxyAddress string) error {
	if !isLoopbackProxyAddress(proxyAddress) {
		return errors.New("Psiphon SOCKS5 proxy must be loopback-only")
	}
	b, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg psiphonClientConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	_, portText, _ := net.SplitHostPort(proxyAddress)
	port, _ := strconv.Atoi(portText)
	if cfg.LocalSocksProxyPort != port {
		return fmt.Errorf("Psiphon config SOCKS5 port %d does not match proxy %s", cfg.LocalSocksProxyPort, proxyAddress)
	}
	if cfg.DisableLocalSocksProxy {
		return errors.New("Psiphon config disables its local SOCKS5 proxy")
	}
	if cfg.UseUnixDomainSockets {
		return errors.New("Psiphon config must use a loopback TCP SOCKS5 listener")
	}
	if _, err := normalizePsiphonEgressRegion(cfg.EgressRegion); err != nil {
		return err
	}
	if cfg.TunnelPoolSize < 1 || cfg.TunnelPoolSize > 16 {
		return fmt.Errorf("invalid Psiphon TunnelPoolSize %d (valid range is 1-16)", cfg.TunnelPoolSize)
	}
	if !isUsablePsiphonClientID(cfg.PropagationChannelID) || !isUsablePsiphonClientID(cfg.SponsorID) || cfg.ClientVersion == "" {
		return errors.New("Psiphon client identity/bootstrap configuration is incomplete or contains placeholder IDs")
	}
	if _, err := strconv.Atoi(cfg.ClientVersion); err != nil {
		return fmt.Errorf("invalid Psiphon ClientVersion: %w", err)
	}
	if cfg.SSHChannelWindowSize != nil && (*cfg.SSHChannelWindowSize < 1 || *cfg.SSHChannelWindowSize > 128) {
		return fmt.Errorf("invalid Psiphon SSHChannelWindowSize %d (valid range is 1-128)", *cfg.SSHChannelWindowSize)
	}
	decodeKey := func(name, value string, minBytes, exactBytes int) error {
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return fmt.Errorf("Psiphon %s is not valid base64: %w", name, err)
		}
		if len(decoded) < minBytes || (exactBytes > 0 && len(decoded) != exactBytes) {
			return fmt.Errorf("Psiphon %s has invalid decoded length %d", name, len(decoded))
		}
		return nil
	}
	if err := decodeKey("RemoteServerListSignaturePublicKey", cfg.RemoteServerListSignaturePublicKey, 256, 0); err != nil {
		return err
	}
	if err := decodeKey("ServerEntrySignaturePublicKey", cfg.ServerEntrySignaturePublicKey, 0, 32); err != nil {
		return err
	}
	if err := decodeKey("ExchangeObfuscationKey", cfg.ExchangeObfuscationKey, 0, 32); err != nil {
		return err
	}
	validateTransfers := func(name string, transfers []psiphonTransferURL) error {
		if len(transfers) == 0 {
			return fmt.Errorf("Psiphon %s is empty", name)
		}
		hasImmediate := false
		for i, transfer := range transfers {
			decoded, decodeErr := base64.StdEncoding.DecodeString(transfer.URL)
			if decodeErr != nil {
				return fmt.Errorf("Psiphon %s[%d] URL is not base64: %w", name, i, decodeErr)
			}
			if !strings.HasPrefix(string(decoded), "https://") {
				return fmt.Errorf("Psiphon %s[%d] URL must use HTTPS", name, i)
			}
			if transfer.OnlyAfterAttempts == 0 {
				hasImmediate = true
			}
		}
		if !hasImmediate {
			return fmt.Errorf("Psiphon %s has no immediate (OnlyAfterAttempts=0) mirror", name)
		}
		return nil
	}
	if cfg.TargetServerEntry == "" {
		if err := validateTransfers("RemoteServerListURLs", cfg.RemoteServerListURLs); err != nil {
			return err
		}
		if err := validateTransfers("ObfuscatedServerListRootURLs", cfg.ObfuscatedServerListRootURLs); err != nil {
			return err
		}
	}
	return nil
}

// parsePsiphonTunnelNotice recognizes the official ConsoleClient Tunnels notice.
// A listening SOCKS port alone is not a connected Psiphon tunnel.
func parsePsiphonTunnelNotice(line string) (int, bool) {
	var notice struct {
		NoticeType string `json:"noticeType"`
		Data       struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(line), &notice) != nil || notice.NoticeType != "Tunnels" {
		return 0, false
	}
	return notice.Data.Count, true
}

func waitForPsiphonProxy(proxyAddress string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		if err := probeSOCKS5(proxyAddress, 700*time.Millisecond); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(350 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("Psiphon SOCKS5 proxy %s is not ready: %w", proxyAddress, lastErr)
	}
	return fmt.Errorf("Psiphon SOCKS5 proxy %s did not become ready", proxyAddress)
}
