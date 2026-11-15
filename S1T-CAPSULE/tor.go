package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	torModeSnowflake     = "snowflake"
	torModeWebTunnel     = "webtunnel"
	torBundleVersion     = "16.0.1"
	torInstallerPath     = "/usr/local/lib/shah-tunnel/install-tor.sh"
	torBundleRoot        = "/usr/local/lib/shah-tunnel/tor-bundle"
	torConfigDir         = "/etc/ravanreverse/tor"
	torDataRoot          = "/var/lib/shah-tunnel/tor"
	torSocksFirstPort    = 19000
	torSocksPortCount    = 1000
	torBootstrapTimeout  = 180 * time.Second
	torRestartDelay      = 4 * time.Second
	torProcessStopWindow = 5 * time.Second
)

// This is the public Snowflake bridge configuration documented by the Tor
// Project. The 192.0.2.3 address is a pluggable-transport placeholder; Snowflake
// obtains a volunteer proxy through its broker rather than dialing that IP.
const defaultSnowflakeBridge = "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org front=www.phpmyadmin.net,cdn.zk.mk ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn"

func validateTorBridgeLine(line string) error {
	line = strings.TrimSpace(line)
	if line == "" || len(line) > 2048 || strings.ContainsAny(line, "\r\n\x00\"#;") {
		return errors.New("invalid Tor WebTunnel bridge line")
	}
	fields := strings.Fields(line)
	if len(fields) < 6 || fields[0] != "Bridge" || fields[1] != "webtunnel" {
		return errors.New("WebTunnel bridge must start with: Bridge webtunnel IP:PORT FINGERPRINT url=https://...")
	}
	if err := validateTCPAddress("Tor WebTunnel bridge address", fields[2]); err != nil {
		return err
	}
	if len(fields[3]) != 40 {
		return errors.New("Tor WebTunnel bridge fingerprint must contain 40 hexadecimal characters")
	}
	if _, err := hex.DecodeString(fields[3]); err != nil {
		return errors.New("Tor WebTunnel bridge fingerprint must be hexadecimal")
	}
	hasURL, hasVersion := false, false
	for _, field := range fields[4:] {
		if strings.HasPrefix(field, "url=https://") && len(strings.TrimPrefix(field, "url=https://")) > 0 {
			hasURL = true
		}
		if field == "ver=0.0.1" {
			hasVersion = true
		}
		if strings.ContainsAny(field, "\"'`\\") {
			return errors.New("unsupported quoting or escape character in Tor WebTunnel bridge line")
		}
	}
	if !hasURL || !hasVersion {
		return errors.New("WebTunnel bridge line must include url=https://... and ver=0.0.1")
	}
	return nil
}

func torBridgeLine(cfg Config) (string, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.TorMode)) {
	case torModeSnowflake:
		return defaultSnowflakeBridge, nil
	case torModeWebTunnel:
		line := strings.TrimSpace(cfg.TorBridge)
		if err := validateTorBridgeLine(line); err != nil {
			return "", err
		}
		return line, nil
	default:
		return "", fmt.Errorf("unsupported Tor transport %q (supported: snowflake, webtunnel)", cfg.TorMode)
	}
}

func buildTorClientConfig(cfg Config) (string, error) {
	bridge, err := torBridgeLine(cfg)
	if err != nil {
		return "", err
	}
	if !isLoopbackProxyAddress(cfg.TorProxy) {
		return "", errors.New("Tor SOCKS5 proxy must listen on loopback")
	}
	for label, path := range map[string]string{
		"Tor data directory": cfg.TorDataDir,
		"Tor config path":    cfg.TorConfigPath,
		"Tor binary":         cfg.TorBinary,
		"Lyrebird binary":    cfg.TorPTBinary,
	} {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, " \t\r\n\x00\"") {
			return "", fmt.Errorf("%s must be an absolute path without whitespace", label)
		}
	}
	if !strings.HasPrefix(filepath.Clean(cfg.TorDataDir)+string(os.PathSeparator), torDataRoot+string(os.PathSeparator)) {
		return "", errors.New("Tor data directory must remain inside the ShahTunnel Tor data root")
	}
	if !strings.HasPrefix(filepath.Clean(cfg.TorConfigPath)+string(os.PathSeparator), torConfigDir+string(os.PathSeparator)) {
		return "", errors.New("Tor configuration must remain inside the ShahTunnel Tor config directory")
	}
	_, port, err := net.SplitHostPort(cfg.TorProxy)
	if err != nil {
		return "", err
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("RunAsDaemon 0\n")
	b.WriteString("ClientOnly 1\n")
	b.WriteString("SafeLogging 1\n")
	b.WriteString("AvoidDiskWrites 1\n")
	b.WriteString("Log notice stdout\n")
	b.WriteString("UseBridges 1\n")
	b.WriteString("DataDirectory " + cfg.TorDataDir + "\n")
	b.WriteString("SocksPort " + cfg.TorProxy + " IsolateSOCKSAuth\n")
	b.WriteString("ClientTransportPlugin snowflake,webtunnel exec " + cfg.TorPTBinary + "\n")
	b.WriteString(bridge + "\n")
	return b.String(), nil
}

func torProfilePortInUse(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

func readUsedTorPorts() map[int]bool {
	used := make(map[int]bool)
	paths := []string{legacyConfigPath}
	entries, err := os.ReadDir(tunnelConfigDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
				paths = append(paths, filepath.Join(tunnelConfigDir, entry.Name()))
			}
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg Config
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr == nil && cfg.TorProxy != "" {
			_, portText, splitErr := net.SplitHostPort(cfg.TorProxy)
			if splitErr == nil {
				if port, parseErr := strconv.Atoi(portText); parseErr == nil {
					used[port] = true
				}
			}
		}
	}
	return used
}

func allocateTorSocksPort(profileName string) (int, error) {
	if strings.TrimSpace(profileName) == "" {
		return 0, errors.New("Tor profile name is required")
	}
	sum := sha256.Sum256([]byte(tunnelID(profileName)))
	start := int(binary.BigEndian.Uint16(sum[:2])) % torSocksPortCount
	used := readUsedTorPorts()
	for offset := 0; offset < torSocksPortCount; offset++ {
		port := torSocksFirstPort + (start+offset)%torSocksPortCount
		if !used[port] && !torProfilePortInUse(port) {
			return port, nil
		}
	}
	return 0, errors.New("no free loopback port is available for this Tor profile")
}

func executableFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}

// nativeELFExecutable rejects debug-symbol artifacts and binaries built for a
// different CPU. A mere executable bit is not enough: execve would otherwise
// fail later with the unhelpful "exec format error" seen on older profiles.
func nativeELFExecutable(path string) bool {
	if !executableFile(path) {
		return false
	}
	f, err := elf.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB {
		return false
	}
	switch runtime.GOARCH {
	case "amd64":
		return f.Machine == elf.EM_X86_64
	case "arm64":
		return f.Machine == elf.EM_AARCH64
	default:
		return false
	}
}

func pathHasDebugComponent(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		part = strings.ToLower(part)
		if part == "debug" || part == "debug-symbols" || part == "symbols" || strings.Contains(part, "debug-symbol") {
			return true
		}
	}
	return false
}

func preferredTorBundlePath(root, name string) string {
	switch name {
	case "tor":
		return filepath.Join(root, "tor", "tor")
	case "lyrebird":
		return filepath.Join(root, "tor", "pluggable_transports", "lyrebird")
	default:
		return ""
	}
}

func findExecutableInTree(root, name string) string {
	// The official Expert Bundle layout is explicit. Prefer it before walking
	// the archive, since debug/tor can appear earlier in lexical directory order.
	preferred := preferredTorBundlePath(root, name)
	if preferred != "" && !pathHasDebugComponent(root, preferred) && nativeELFExecutable(preferred) {
		return preferred
	}

	var candidates []string
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() || entry.Name() != name || pathHasDebugComponent(root, path) {
			return nil
		}
		if nativeELFExecutable(path) {
			candidates = append(candidates, path)
		}
		return nil
	})
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		relI, _ := filepath.Rel(root, candidates[i])
		relJ, _ := filepath.Rel(root, candidates[j])
		depthI, depthJ := strings.Count(relI, string(os.PathSeparator)), strings.Count(relJ, string(os.PathSeparator))
		if depthI != depthJ {
			return depthI < depthJ
		}
		return relI < relJ
	})
	return candidates[0]
}

func locateTorBinaries() (string, string) {
	torBinary := findExecutableInTree(torBundleRoot, "tor")
	ptBinary := findExecutableInTree(torBundleRoot, "lyrebird")
	if torBinary == "" {
		torBinary, _ = exec.LookPath("tor")
	}
	if ptBinary == "" {
		ptBinary, _ = exec.LookPath("lyrebird")
	}
	if !nativeELFExecutable(torBinary) || !nativeELFExecutable(ptBinary) {
		return "", ""
	}
	return torBinary, ptBinary
}

func validateTorBinary(path string) error {
	if !nativeELFExecutable(path) {
		return fmt.Errorf("Tor executable is not a native Linux/%s ELF binary: %s", runtime.GOARCH, path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Env = torRuntimeEnvironment(Config{TorBinary: path})
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return errors.New("Tor --version self-test timed out")
	}
	if err != nil {
		return fmt.Errorf("Tor --version self-test failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !strings.Contains(strings.ToLower(string(output)), "tor version") {
		return fmt.Errorf("unexpected output from Tor executable %s: %s", path, strings.TrimSpace(string(output)))
	}
	return nil
}

func torBundleVersionInstalled() string {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(torBundleRoot), "tor-bundle.info"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "version=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "version="))
		}
	}
	return ""
}

func isTorBundlePath(path string) bool {
	clean := filepath.Clean(path)
	root := filepath.Clean(torBundleRoot) + string(os.PathSeparator)
	return strings.HasPrefix(clean+string(os.PathSeparator), root)
}

func ensureTorBinaries() (string, string, error) {
	torBinary, ptBinary := locateTorBinaries()
	if torBinary != "" && ptBinary != "" {
		// System Tor installations are left alone. A ShahTunnel-managed bundle,
		// however, is reused only when its pinned metadata matches the current
		// supported release. Always execute --version before trusting a path.
		if err := validateTorBinary(torBinary); err == nil && nativeELFExecutable(ptBinary) {
			if !isTorBundlePath(torBinary) || torBundleVersionInstalled() == torBundleVersion {
				return torBinary, ptBinary, nil
			}
		}
	}
	oldTorBinary, oldPTBinary := torBinary, ptBinary
	fallbackToExisting := func(reason error) (string, string, error) {
		if validateTorBinary(oldTorBinary) == nil && nativeELFExecutable(oldPTBinary) {
			log.Printf("WARNING: could not upgrade the existing Tor bundle to %s; continuing with the previously installed Tor/Lyrebird binaries so this Agent can still start: %v", torBundleVersion, reason)
			return oldTorBinary, oldPTBinary, nil
		}
		return "", "", reason
	}
	if _, err := os.Stat(torInstallerPath); err != nil {
		return fallbackToExisting(errors.New("Tor installer is missing; rerun the updated ShahTunnel installer"))
	}
	// Keep an upgrade attempt bounded. The installer stages and verifies a new
	// archive before swapping directories, so timeout/failure leaves the old
	// bundle in place and usable.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", torInstallerPath)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fallbackToExisting(errors.New("Tor Expert Bundle upgrade timed out after 90 seconds"))
	}
	if err != nil {
		return fallbackToExisting(fmt.Errorf("Tor transport installation failed: %w: %s", err, strings.TrimSpace(string(output))))
	}
	torBinary, ptBinary = locateTorBinaries()
	if torBinary == "" || ptBinary == "" {
		return fallbackToExisting(errors.New("Tor installer completed but native-architecture tor/lyrebird executables could not be found outside debug directories"))
	}
	if err := validateTorBinary(torBinary); err != nil {
		return fallbackToExisting(fmt.Errorf("Tor installer completed but the selected runtime Tor binary failed its native execution check: %w", err))
	}
	if !nativeELFExecutable(ptBinary) {
		return fallbackToExisting(fmt.Errorf("Tor installer completed but Lyrebird is not a native Linux/%s ELF binary: %s", runtime.GOARCH, ptBinary))
	}
	if isTorBundlePath(torBinary) && torBundleVersionInstalled() != torBundleVersion {
		return fallbackToExisting(fmt.Errorf("Tor installer completed but bundle metadata is not %s", torBundleVersion))
	}
	return torBinary, ptBinary, nil
}

func prepareTorAgentProfile(cfg *Config) error {
	if cfg == nil || cfg.Role != "agent" || cfg.Underlay != underlayTor {
		return errors.New("Tor can only be prepared for an Agent profile selecting Tor egress")
	}
	if _, err := torBridgeLine(*cfg); err != nil {
		return err
	}
	torBinary, ptBinary, err := ensureTorBinaries()
	if err != nil {
		return err
	}
	port, err := allocateTorSocksPort(cfg.Name)
	if err != nil {
		return err
	}
	profileID := tunnelID(cfg.Name)
	dataDir := filepath.Join(torDataRoot, profileID)
	configPath := filepath.Join(torConfigDir, profileID+".torrc")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create Tor data directory: %w", err)
	}
	if err := os.Chmod(dataDir, 0700); err != nil {
		return fmt.Errorf("secure Tor data directory: %w", err)
	}
	if err := os.MkdirAll(torConfigDir, 0700); err != nil {
		return fmt.Errorf("create Tor config directory: %w", err)
	}
	cfg.TorProxy = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	cfg.TorDataDir = dataDir
	cfg.TorConfigPath = configPath
	cfg.TorBinary = torBinary
	cfg.TorPTBinary = ptBinary
	return nil
}

func scanTorLog(reader io.Reader, bootstrap chan<- struct{}) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		log.Printf("Tor: %s", line)
		if strings.Contains(strings.ToLower(line), "bootstrapped 100%") {
			select {
			case bootstrap <- struct{}{}:
			default:
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Tor log stream ended: %v", err)
	}
}

// torAgentReadinessFromJournal distinguishes a running systemd process from a
// usable Tor tunnel. Provisioning the binaries and reserving a SOCKS port do not
// prove that Tor has bootstrapped or that an authenticated Hub lane is alive.
func torAgentReadinessFromJournal(logText string) (bootstrapped, laneConnected bool) {
	for _, line := range strings.Split(logText, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Tor transport bootstrapped successfully") {
			bootstrapped = true
		}
		if strings.Contains(line, "tunnel lane ") &&
			strings.Contains(line, " connected via ") &&
			strings.Contains(line, " over tor_socks5") {
			laneConnected = true
		}
	}
	return bootstrapped, laneConnected
}

func torRuntimeEnvironment(cfg Config) []string {
	base := os.Environ()
	var env []string
	for _, item := range base {
		if !strings.HasPrefix(item, "LD_LIBRARY_PATH=") {
			env = append(env, item)
		}
	}
	paths := make([]string, 0, 3)
	if strings.HasPrefix(filepath.Clean(cfg.TorBinary), torBundleRoot+string(os.PathSeparator)) || filepath.Clean(filepath.Dir(cfg.TorBinary)) == torBundleRoot {
		paths = append(paths, filepath.Dir(cfg.TorBinary))
	}
	if strings.HasPrefix(filepath.Clean(cfg.TorPTBinary), torBundleRoot+string(os.PathSeparator)) || filepath.Clean(filepath.Dir(cfg.TorPTBinary)) == torBundleRoot {
		paths = append(paths, filepath.Dir(cfg.TorPTBinary))
	}
	if existing := strings.TrimSpace(os.Getenv("LD_LIBRARY_PATH")); existing != "" {
		paths = append(paths, strings.Split(existing, string(os.PathListSeparator))...)
	}
	seen := make(map[string]bool, len(paths))
	unique := paths[:0]
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path != "" && !seen[path] {
			seen[path] = true
			unique = append(unique, path)
		}
	}
	if len(unique) > 0 {
		env = append(env, "LD_LIBRARY_PATH="+strings.Join(unique, string(os.PathListSeparator)))
	}
	return env
}

func torCommand(cfg Config, args ...string) *exec.Cmd {
	cmd := exec.Command(cfg.TorBinary, args...)
	cmd.Env = torRuntimeEnvironment(cfg)
	return cmd
}

func launchTorProcess(cfg Config) (*exec.Cmd, <-chan error, <-chan struct{}, error) {
	cmd := torCommand(cfg, "-f", cfg.TorConfigPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open Tor stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open Tor stderr: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, fmt.Errorf("start Tor: %w", err)
	}
	bootstrap := make(chan struct{}, 1)
	go scanTorLog(stdout, bootstrap)
	go scanTorLog(stderr, bootstrap)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	return cmd, done, bootstrap, nil
}

func stopTorProcess(cmd *exec.Cmd, done <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(torProcessStopWindow)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func startTorForAgent(cfg Config) (func(), error) {
	if cfg.Underlay != underlayTor {
		return func() {}, nil
	}
	// Refresh ShahTunnel-managed Tor bundles on service start as well as during
	// profile creation. This upgrades existing profiles without deleting their
	// saved configuration or Tor data directory.
	torBinary, ptBinary, err := ensureTorBinaries()
	if err != nil {
		return nil, fmt.Errorf("prepare the Tor Expert Bundle for this Agent: %w", err)
	}
	cfg.TorBinary = torBinary
	cfg.TorPTBinary = ptBinary
	if err := validateTorBinary(cfg.TorBinary); err != nil {
		return nil, fmt.Errorf("selected Tor executable failed validation: %w", err)
	}
	if !nativeELFExecutable(cfg.TorPTBinary) {
		return nil, fmt.Errorf("selected Lyrebird executable is not a native Linux/%s ELF binary: %s", runtime.GOARCH, cfg.TorPTBinary)
	}
	if !isLoopbackProxyAddress(cfg.TorProxy) {
		return nil, errors.New("Tor SOCKS5 proxy must be loopback-only")
	}
	if err := os.MkdirAll(cfg.TorDataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(cfg.TorDataDir, 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.TorConfigPath), 0700); err != nil {
		return nil, err
	}
	torrc, err := buildTorClientConfig(cfg)
	if err != nil {
		return nil, err
	}
	if err := atomicWriteFile(cfg.TorConfigPath, []byte(torrc), 0600); err != nil {
		return nil, fmt.Errorf("write Tor client configuration: %w", err)
	}
	verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 12*time.Second)
	verifyCmd := exec.CommandContext(verifyCtx, cfg.TorBinary, "--verify-config", "-f", cfg.TorConfigPath)
	verifyCmd.Env = torRuntimeEnvironment(cfg)
	verifyOutput, verifyErr := verifyCmd.CombinedOutput()
	verifyCancel()
	if verifyErr != nil {
		return nil, fmt.Errorf("Tor configuration validation failed: %w: %s", verifyErr, strings.TrimSpace(string(verifyOutput)))
	}

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	startupErr := make(chan error, 1)
	supervisorDone := make(chan struct{})
	go func() {
		defer close(supervisorDone)
		firstStart := true
		for {
			cmd, processDone, bootstrap, launchErr := launchTorProcess(cfg)
			if launchErr != nil {
				if firstStart {
					startupErr <- launchErr
					return
				}
				log.Printf("Tor supervisor: could not restart Tor: %v", launchErr)
			} else {
				bootstrapTimer := time.NewTimer(torBootstrapTimeout)
				select {
				case <-bootstrap:
					if firstStart {
						close(ready)
						firstStart = false
					}
					bootstrapTimer.Stop()
					log.Printf("Tor transport bootstrapped successfully; SOCKS5 proxy is %s", cfg.TorProxy)
					select {
					case processErr := <-processDone:
						log.Printf("Tor process exited; retrying in %s: %v", torRestartDelay, processErr)
					case <-ctx.Done():
						stopTorProcess(cmd, processDone)
						return
					}
				case processErr := <-processDone:
					if !bootstrapTimer.Stop() {
						select {
						case <-bootstrapTimer.C:
						default:
						}
					}
					if firstStart {
						startupErr <- fmt.Errorf("Tor exited before bootstrap completed: %v", processErr)
						return
					}
					log.Printf("Tor process exited before bootstrap; retrying in %s: %v", torRestartDelay, processErr)
				case <-bootstrapTimer.C:
					stopTorProcess(cmd, processDone)
					if firstStart {
						startupErr <- fmt.Errorf("Tor did not bootstrap within %s", torBootstrapTimeout)
						return
					}
					log.Printf("Tor restart did not bootstrap within %s", torBootstrapTimeout)
				case <-ctx.Done():
					if !bootstrapTimer.Stop() {
						select {
						case <-bootstrapTimer.C:
						default:
						}
					}
					stopTorProcess(cmd, processDone)
					return
				}
			}
			if ctx.Err() != nil {
				return
			}
			timer := time.NewTimer(torRestartDelay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			}
		}
	}()

	select {
	case <-ready:
		if err := probeSOCKS5(cfg.TorProxy, 2*time.Second); err != nil {
			cancel()
			<-supervisorDone
			return nil, fmt.Errorf("Tor reported bootstrap complete but its local SOCKS5 endpoint is unavailable: %w", err)
		}
		return func() {
			cancel()
			select {
			case <-supervisorDone:
			case <-time.After(8 * time.Second):
				log.Printf("Tor supervisor did not stop within the cleanup window")
			}
		}, nil
	case err := <-startupErr:
		cancel()
		<-supervisorDone
		return nil, err
	case <-time.After(torBootstrapTimeout + 10*time.Second):
		cancel()
		<-supervisorDone
		return nil, errors.New("Tor startup did not complete before the bootstrap deadline")
	}
}
