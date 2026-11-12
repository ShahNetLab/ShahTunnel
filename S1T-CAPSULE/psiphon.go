package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
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

const (
	psiphonConsoleClientPath = "/usr/local/bin/psiphon-console-client"
	psiphonInstallerPath     = "/usr/local/lib/shah-tunnel/install-psiphon.sh"
	psiphonConfigDir         = "/etc/ravanreverse/psiphon"
	psiphonDataRoot          = "/var/lib/shah-tunnel/psiphon"

	// Psiphon ConsoleClient v2.0.41 public-network bootstrap values.
	// These are runtime client settings; no private server entry is embedded.
	psiphonPropagationChannelID = "FFFFFFFFFFFFFFFF"
	psiphonSponsorID            = "FFFFFFFFFFFFFFFF"
	psiphonRemoteServerListURL  = "https://s3.amazonaws.com/psiphon/web/mjr4-p23r-puwl/server_list_compressed"
	psiphonRemoteServerListKey  = "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM="
)

// psiphonClientConfig is intentionally limited to ConsoleClient's SOCKS mode.
// No TUN device or host routing is configured by ShahTunnel.
type psiphonClientConfig struct {
	ClientVersion                      string `json:"ClientVersion"`
	ClientPlatform                     string `json:"ClientPlatform"`
	PropagationChannelID               string `json:"PropagationChannelId"`
	SponsorID                          string `json:"SponsorId"`
	EgressRegion                       string `json:"EgressRegion"`
	LocalSocksProxyPort                int    `json:"LocalSocksProxyPort"`
	DisableLocalSocksProxy             bool   `json:"DisableLocalSocksProxy,omitempty"`
	DisableLocalHTTPProxy              bool   `json:"DisableLocalHTTPProxy"`
	UseUnixDomainSockets               bool   `json:"UseUnixDomainSockets"`
	TargetServerEntry                  string `json:"TargetServerEntry,omitempty"`
	RemoteServerListDownloadFilename   string `json:"RemoteServerListDownloadFilename"`
	RemoteServerListSignaturePublicKey string `json:"RemoteServerListSignaturePublicKey,omitempty"`
	RemoteServerListURL                string `json:"RemoteServerListUrl,omitempty"`
	UseIndistinguishableTLS            bool   `json:"UseIndistinguishableTLS"`
	LimitMeekBufferSizes               bool   `json:"LimitMeekBufferSizes"`
	LimitCPUThreads                    bool   `json:"LimitCPUThreads"`
	LimitRelayBufferSizes              bool   `json:"LimitRelayBufferSizes"`
	ConnectionWorkerPoolMaxSize        int    `json:"ConnectionWorkerPoolMaxSize"`
}

func newPsiphonClientConfig(port int) psiphonClientConfig {
	return psiphonClientConfig{
		ClientVersion:                      "1",
		ClientPlatform:                     "Linux",
		PropagationChannelID:               psiphonPropagationChannelID,
		SponsorID:                          psiphonSponsorID,
		EgressRegion:                       "",
		LocalSocksProxyPort:                port,
		DisableLocalHTTPProxy:              true,
		UseUnixDomainSockets:               false,
		RemoteServerListDownloadFilename:   "remote_server_list",
		RemoteServerListSignaturePublicKey: psiphonRemoteServerListKey,
		RemoteServerListURL:                psiphonRemoteServerListURL,
		UseIndistinguishableTLS:            true,
		LimitMeekBufferSizes:               true,
		LimitCPUThreads:                    true,
		LimitRelayBufferSizes:              true,
		ConnectionWorkerPoolMaxSize:        2,
	}
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
	if cfg.PropagationChannelID == "" || cfg.SponsorID == "" || cfg.ClientVersion == "" {
		return errors.New("Psiphon client identity/bootstrap configuration is incomplete")
	}
	if _, err := strconv.Atoi(cfg.ClientVersion); err != nil {
		return fmt.Errorf("invalid Psiphon ClientVersion: %w", err)
	}
	// A ConsoleClient needs a seed entry, or the authenticated remote server
	// list bootstrap (URL + signing key) to discover Psiphon relays.
	if cfg.TargetServerEntry == "" && (cfg.RemoteServerListURL == "" || cfg.RemoteServerListSignaturePublicKey == "") {
		return errors.New("Psiphon has no TargetServerEntry or authenticated remote server-list bootstrap")
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
