package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const openVPNRouteHelperPath = "/usr/local/lib/shah-tunnel/openvpn-route.sh"

type openVPNRouteInfo struct {
	Table    int
	Mark     int
	Priority int
	Device   string
}

func openVPNRouteInfoForProfile(profile string) openVPNRouteInfo {
	sum := sha256.Sum256([]byte(tunnelID(profile)))
	deviceSuffix := hex.EncodeToString(sum[12:17])
	return openVPNRouteInfo{
		Table: 20000 + int(binary.BigEndian.Uint32(sum[0:4])%1_000_000_000),
		Mark:  0x53000000 | int(binary.BigEndian.Uint32(sum[4:8])&0x00ffffff),
		// Both the active lookup rule (10k-20k) and its blackhole
		// fallback (+10k) must run before Linux's main rule (32766).
		// Equal priorities across profiles are safe because each rule
		// matches a distinct per-profile fwmark.
		Priority: 10000 + int(binary.BigEndian.Uint32(sum[8:12])%10_000),
		Device:   "tun" + deviceSuffix,
	}
}

func openVPNProfileDir(profile string) string {
	return filepath.Join("/etc/ravanreverse/openvpn", tunnelID(profile))
}

func openVPNServiceName(profile string) string {
	return "shah-tunnel-openvpn-" + tunnelID(profile) + ".service"
}

func openVPNRouteHelperScript() []byte {
	return []byte(`#!/bin/sh
set -eu
ACTION="${1:-}"
TABLE="${2:-}"
MARK="${3:-}"
PRIORITY="${4:-}"
DEV="${5:-${dev:-}}"
BLACKHOLE_PRIORITY=$((PRIORITY + 10000))
IP="/usr/sbin/ip"
[ -x "$IP" ] || IP="$(command -v ip || true)"
[ -n "$IP" ] || { echo "iproute2 is required" >&2; exit 1; }
case "$TABLE:$MARK:$PRIORITY" in *[!0-9:]*|::*|*::* ) echo "invalid route metadata" >&2; exit 2;; esac
MARK_HEX="$(printf '0x%x' "$MARK")"
blackhole_routes() {
  "$IP" -4 route replace blackhole default table "$TABLE"
  if "$IP" -6 rule show >/dev/null 2>&1; then
    "$IP" -6 route replace blackhole default table "$TABLE"
  fi
}
remove_lookup_rules() {
  "$IP" -4 rule del priority "$PRIORITY" fwmark "$MARK"/0xffffffff lookup "$TABLE" 2>/dev/null || true
  if "$IP" -6 rule show >/dev/null 2>&1; then
    "$IP" -6 rule del priority "$PRIORITY" fwmark "$MARK"/0xffffffff lookup "$TABLE" 2>/dev/null || true
  fi
}
case "$ACTION" in
  init)
    # Install an explicit blackhole policy rule BEFORE OpenVPN starts. This is
    # the fail-closed guard even if a table route or the VPN interface is absent.
    blackhole_routes
    if ! "$IP" -4 rule show | grep -q "fwmark $MARK_HEX.*blackhole"; then
      "$IP" -4 rule add priority "$BLACKHOLE_PRIORITY" fwmark "$MARK"/0xffffffff blackhole
    fi
    if "$IP" -6 rule show >/dev/null 2>&1; then
      if ! "$IP" -6 rule show | grep -q "fwmark $MARK_HEX.*blackhole"; then
        "$IP" -6 rule add priority "$BLACKHOLE_PRIORITY" fwmark "$MARK"/0xffffffff blackhole
      fi
    fi
    ;;
  up)
    [ -n "$DEV" ] || { echo "OpenVPN did not provide a TUN device" >&2; exit 3; }
    # Install routes first; only then add the higher-priority lookup rule.
    "$IP" -4 route replace default dev "$DEV" table "$TABLE"
    if ! "$IP" -4 rule show | grep -q "fwmark $MARK_HEX.*lookup $TABLE"; then
      "$IP" -4 rule add priority "$PRIORITY" fwmark "$MARK"/0xffffffff lookup "$TABLE"
    fi
    if "$IP" -6 rule show >/dev/null 2>&1; then
      # If the provider has no usable IPv6 path, keep the IPv6 blackhole rule.
      if "$IP" -6 route replace default dev "$DEV" table "$TABLE" 2>/dev/null; then
        if ! "$IP" -6 rule show | grep -q "fwmark $MARK_HEX.*lookup $TABLE"; then
          "$IP" -6 rule add priority "$PRIORITY" fwmark "$MARK"/0xffffffff lookup "$TABLE"
        fi
      fi
    fi
    ;;
  down)
    # Remove the lookup rule first; the lower-priority blackhole rule remains.
    remove_lookup_rules
    blackhole_routes
    ;;
  remove)
    remove_lookup_rules
    "$IP" -4 rule del priority "$BLACKHOLE_PRIORITY" fwmark "$MARK"/0xffffffff blackhole 2>/dev/null || true
    if "$IP" -6 rule show >/dev/null 2>&1; then
      "$IP" -6 rule del priority "$BLACKHOLE_PRIORITY" fwmark "$MARK"/0xffffffff blackhole 2>/dev/null || true
    fi
    "$IP" -4 route flush table "$TABLE" 2>/dev/null || true
    if "$IP" -6 rule show >/dev/null 2>&1; then
      "$IP" -6 route flush table "$TABLE" 2>/dev/null || true
    fi
    ;;
  *) echo "usage: $0 {init|up|down|remove} TABLE MARK PRIORITY [DEV]" >&2; exit 2;;
esac
`)
}

func runOpenVPNPackageCommand(label string, timeout time.Duration, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "apt-get", args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	// Stream apt output directly to the interactive terminal. The previous
	// CombinedOutput implementation buffered everything, making a slow apt
	// mirror look like the ShahTunnel wizard had frozen after option 3.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	uiInfo(label)
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("%s timed out after %s; check apt repository/network availability", strings.Join(args, " "), timeout)
		}
		return fmt.Errorf("%s failed: %w", strings.Join(args, " "), err)
	}
	return nil
}

func ensureOpenVPNInstalled() error {
	openVPNErr := func() error { _, err := exec.LookPath("openvpn"); return err }()
	ipErr := func() error { _, err := exec.LookPath("ip"); return err }()
	if openVPNErr == nil && ipErr == nil {
		uiInfo("OpenVPN and iproute2 are already installed.")
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("OpenVPN installation requires root")
	}
	if _, err := exec.LookPath("apt-get"); err != nil {
		return errors.New("OpenVPN is not installed and this system has no apt-get package manager; install openvpn and iproute2 first")
	}
	if err := runOpenVPNPackageCommand("Updating APT package indexes (progress is shown below)...", 8*time.Minute, "-o", "Dpkg::Use-Pty=0", "-o", "Acquire::Retries=2", "update"); err != nil {
		return fmt.Errorf("APT package index update failed: %w", err)
	}
	if err := runOpenVPNPackageCommand("Installing OpenVPN and iproute2 (progress is shown below)...", 8*time.Minute, "-o", "Dpkg::Use-Pty=0", "install", "-y", "openvpn", "iproute2"); err != nil {
		return fmt.Errorf("OpenVPN dependency installation failed: %w", err)
	}
	if _, err := exec.LookPath("openvpn"); err != nil {
		return fmt.Errorf("OpenVPN package installed but binary is not available: %w", err)
	}
	if _, err := exec.LookPath("ip"); err != nil {
		return fmt.Errorf("iproute2 package installed but ip binary is not available: %w", err)
	}
	return nil
}

func tailText(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return s
}

func openVPNDirective(line string) (string, []string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") || strings.HasPrefix(trimmed, "<") || strings.HasPrefix(trimmed, ">") {
		return "", nil
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", nil
	}
	return strings.ToLower(fields[0]), fields[1:]
}

func sanitizeOpenVPNProfile(src, dst, authPath, profile, helper string, route openVPNRouteInfo) (string, error) {
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return "", err
	}
	input, err := os.Open(absSrc)
	if err != nil {
		return "", fmt.Errorf("open provider .ovpn file: %w", err)
	}
	defer input.Close()
	baseDir := filepath.Dir(absSrc)
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return "", err
	}
	var lines []string
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	insideBlock := false
	protoTCP, remoteSeen, caSeen, authSeen := false, false, false, false
	var authSource string
	blocked := map[string]bool{
		"dev": true, "dev-type": true, "proto": true, "route": true, "route-ipv6": true, "redirect-gateway": true, "redirect-private": true,
		"route-gateway": true, "route-delay": true, "route-method": true, "route-nopull": true, "route-noexec": true, "up": true, "down": true,
		"route-up": true, "route-pre-down": true, "ipchange": true, "learn-address": true, "client-connect": true, "client-disconnect": true,
		"plugin": true, "script-security": true, "daemon": true, "log": true, "log-append": true, "status": true, "writepid": true,
		"management": true, "cd": true, "config": true, "user": true, "group": true, "auth-user-pass": true, "auth-user-pass-verify": true, "tls-verify": true, "ifconfig": true, "ifconfig-ipv6": true,
		"persist-tun": true, "persist-key": true, "setenv": true,
	}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<") && !strings.HasPrefix(trimmed, "</") {
			allowedBlock := map[string]bool{"<ca>": true, "<cert>": true, "<key>": true, "<tls-crypt>": true, "<tls-crypt-v2>": true, "<tls-auth>": true, "<pkcs12>": true, "<dh>": true, "<extra-certs>": true, "<secret>": true}
			if !allowedBlock[strings.ToLower(trimmed)] {
				return "", fmt.Errorf("unsupported OpenVPN inline block %q; connection/script blocks are not accepted", trimmed)
			}
			if strings.EqualFold(trimmed, "<ca>") {
				caSeen = true
			}
			insideBlock = true
		}
		if insideBlock {
			lines = append(lines, line)
			if strings.HasPrefix(trimmed, "</") {
				insideBlock = false
			}
			continue
		}
		key, args := openVPNDirective(line)
		if key == "" {
			lines = append(lines, line)
			continue
		}
		if key == "proto" {
			if len(args) == 0 || !(strings.EqualFold(args[0], "tcp") || strings.EqualFold(args[0], "tcp-client")) {
				return "", fmt.Errorf("provider profile uses non-TCP OpenVPN protocol %q; download the TCP profile", strings.Join(args, " "))
			}
			protoTCP = true
			continue
		}
		if key == "remote" {
			remoteSeen = true
			if len(args) >= 3 && strings.EqualFold(args[2], "udp") {
				return "", errors.New("a remote entry overrides the TCP protocol with UDP; download a TCP-only profile")
			}
		}
		if key == "remote-cert-tls" {
			if len(args) == 0 || !strings.EqualFold(args[0], "server") {
				return "", errors.New("provider profile must verify the remote as a TLS server")
			}
		}
		if key == "ca" {
			caSeen = true
		}
		if key == "auth-user-pass" {
			authSeen = true
			if len(args) > 0 {
				authSource = args[0]
			}
			continue
		}
		if blocked[key] {
			continue
		}
		if len(args) > 0 {
			switch key {
			case "ca", "cert", "key", "dh", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs", "crl-verify", "pkcs12", "askpass":
				if !strings.HasPrefix(args[0], "<") {
					sourceFile := args[0]
					if !filepath.IsAbs(sourceFile) {
						sourceFile = filepath.Join(baseDir, sourceFile)
					}
					data, e := os.ReadFile(sourceFile)
					if e != nil {
						return "", fmt.Errorf("OpenVPN referenced file %q is unavailable: %w", args[0], e)
					}
					hash := sha256.Sum256([]byte(filepath.Clean(sourceFile)))
					name := filepath.Base(sourceFile) + "-" + fmt.Sprintf("%x", hash[:4])
					destination := filepath.Join(filepath.Dir(dst), name)
					if e = os.WriteFile(destination, data, 0600); e != nil {
						return "", e
					}
					args[0] = destination
					line = key + " " + strings.Join(args, " ")
				}
			}
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if !protoTCP {
		return "", errors.New("the .ovpn profile must explicitly contain 'proto tcp' or 'proto tcp-client'")
	}
	if !remoteSeen {
		return "", errors.New("the .ovpn profile has no remote server entry")
	}
	if !caSeen {
		return "", errors.New("OpenVPN profile must include a CA certificate so the remote TLS server can be authenticated")
	}
	if authSeen {
		if authSource == "" {
			authSource = authPath
		}
		if authSource == "" {
			return "", errors.New("this provider profile requires username/password; provide a private credentials file with username on line 1 and password on line 2")
		}
		if !filepath.IsAbs(authSource) {
			authSource = filepath.Join(baseDir, authSource)
		}
		secret, err := os.ReadFile(authSource)
		if err != nil {
			return "", fmt.Errorf("OpenVPN credentials file is unavailable: %w", err)
		}
		credentialLines := strings.Split(strings.TrimRight(string(secret), "\r\n"), "\n")
		if len(credentialLines) < 2 || strings.TrimSpace(credentialLines[0]) == "" || strings.TrimSpace(credentialLines[1]) == "" {
			return "", errors.New("OpenVPN credentials file must contain username on line 1 and password on line 2")
		}
		managedAuth := filepath.Join(filepath.Dir(dst), "auth.txt")
		if err := os.WriteFile(managedAuth, secret, 0600); err != nil {
			return "", err
		}
		lines = append(lines, "auth-user-pass "+managedAuth)
	}
	if !containsOpenVPNDirective(lines, "remote-cert-tls") {
		lines = append(lines, "remote-cert-tls server")
	}
	lines = append(lines,
		"client", "dev "+route.Device, "proto tcp-client", "route-nopull", "persist-key", "persist-tun", "auth-nocache",
		"script-security 2", "up "+helper+" up "+strconv.Itoa(route.Table)+" "+strconv.Itoa(route.Mark)+" "+strconv.Itoa(route.Priority),
		"down "+helper+" down "+strconv.Itoa(route.Table)+" "+strconv.Itoa(route.Mark)+" "+strconv.Itoa(route.Priority), "down-pre", "verb 3")
	if err := os.WriteFile(dst, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		return "", err
	}
	return baseDir, nil
}

func containsOpenVPNDirective(lines []string, directive string) bool {
	for _, line := range lines {
		key, _ := openVPNDirective(line)
		if key == directive {
			return true
		}
	}
	return false
}

func installOpenVPNRouteHelper() error {
	if err := os.MkdirAll(filepath.Dir(openVPNRouteHelperPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(openVPNRouteHelperPath, openVPNRouteHelperScript(), 0755); err != nil {
		return err
	}
	return os.Chmod(openVPNRouteHelperPath, 0755)
}

func renderOpenVPNUnit(profile, configPath, workDir string, route openVPNRouteInfo, restartOnFailure bool) ([]byte, error) {
	if configPath == "" || !filepath.IsAbs(configPath) || strings.ContainsAny(configPath+workDir, "\x00\r\n") {
		return nil, errors.New("invalid OpenVPN service paths")
	}
	bin, err := exec.LookPath("openvpn")
	if err != nil {
		return nil, err
	}
	restartDirective := "Restart=no"
	if restartOnFailure {
		restartDirective = "Restart=always\nRestartSec=3"
	}
	unit := fmt.Sprintf(`[Unit]
Description=ShahTunnel isolated OpenVPN TCP egress (%s)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
UMask=0077
WorkingDirectory=%s
ExecStartPre=%s init %d %d %d
ExecStart=%s --config %s
ExecStopPost=%s down %d %d %d
%s
TimeoutStopSec=20
LimitNOFILE=65536
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=no
ProtectSystem=full
ProtectHome=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
DeviceAllow=/dev/net/tun rw
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=%s /run

[Install]
WantedBy=multi-user.target
`, tunnelID(profile), systemdExecQuote(workDir), openVPNRouteHelperPath, route.Table, route.Mark, route.Priority, bin, systemdExecQuote(configPath), openVPNRouteHelperPath, route.Table, route.Mark, route.Priority, restartDirective, filepath.Dir(configPath))
	return []byte(unit), nil
}

func installOpenVPNAgentCapabilities(profile string) error {
	service := "ravanreverse@" + tunnelID(profile) + ".service"
	dir := filepath.Join("/etc/systemd/system", service+".d")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	content := []byte("[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW\n")
	if err := os.WriteFile(filepath.Join(dir, "20-openvpn-mark.conf"), content, 0644); err != nil {
		return err
	}
	return systemdReload()
}

func prepareOpenVPNAgentProfile(c *Config) error {
	if c == nil || c.Role != "agent" {
		return errors.New("free OpenVPN egress can only be configured for an Agent")
	}
	if !isRoot() {
		return errors.New("run the manager as root to prepare the private VPN Gate OpenVPN profile")
	}
	uiInfo("Fetching the official VPN Gate free public relay list and filtering TCP servers…")
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	servers, err := fetchVPNGateServers(ctx)
	cancel()
	if err != nil {
		return err
	}
	countryCode, err := chooseVPNGateCountry(servers)
	if err != nil {
		return err
	}
	filtered := make([]vpnGateServer, 0, len(servers))
	for _, server := range servers {
		if countryCode == "" || server.CountryCode == countryCode {
			filtered = append(filtered, server)
		}
	}
	if len(filtered) == 0 {
		return errors.New("VPN Gate has no TCP relay for the selected country; refresh the list or choose Automatic")
	}
	uiInfo(fmt.Sprintf("Testing TCP reachability for %d VPN Gate relays; ranking by reported ping, speed and load…", len(filtered)))
	candidates := probeVPNGateServers(filtered, 5)
	if len(candidates) == 0 {
		return errors.New("no VPN Gate TCP server responded to the reachability check; choose another country or retry later")
	}
	uiInfo(fmt.Sprintf("Found %d reachable VPN Gate TCP candidates. ShahTunnel will try them automatically until one connects.", len(candidates)))

	if err := ensureOpenVPNInstalled(); err != nil {
		return err
	}
	profileDir := openVPNProfileDir(c.Name)
	unitPath := filepath.Join("/etc/systemd/system", openVPNServiceName(c.Name))
	if _, err := os.Stat(unitPath); err == nil {
		return fmt.Errorf("managed OpenVPN service %s already exists; remove or repair the existing Agent profile before reusing its name", filepath.Base(unitPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dropInPath := filepath.Join("/etc/systemd/system", "ravanreverse@"+tunnelID(c.Name)+".service.d", "20-openvpn-mark.conf")
	if _, err := os.Stat(dropInPath); err == nil {
		return fmt.Errorf("OpenVPN capability drop-in already exists for Agent %s; refusing to overwrite it", c.Name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(profileDir); err == nil {
		return fmt.Errorf("managed OpenVPN directory already exists for Agent %s; remove or repair the old profile first", c.Name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(profileDir, 0700); err != nil {
		return err
	}
	_ = os.Chmod(profileDir, 0700)
	rollbackDir := func() { _ = os.RemoveAll(profileDir) }

	// VPN Gate publishes the shared public credentials in its official
	// connection guide. They are written locally with owner-only permissions;
	// no account, API key or user-supplied profile is required.
	authPath := filepath.Join(profileDir, "vpngate-auth.txt")
	if err := os.WriteFile(authPath, []byte("vpn\nvpn\n"), 0600); err != nil {
		rollbackDir()
		return err
	}
	route := openVPNRouteInfoForProfile(c.Name)
	if err := installOpenVPNRouteHelper(); err != nil {
		rollbackDir()
		return err
	}
	if err := installOpenVPNAgentCapabilities(c.Name); err != nil {
		_ = os.Remove(dropInPath)
		_ = systemdReload()
		rollbackDir()
		return err
	}
	rollbackCapabilities := func() {
		_ = os.Remove(dropInPath)
		_ = systemdReload()
	}
	managedConfig := filepath.Join(profileDir, "client.ovpn")
	c.OpenVPNConfig = managedConfig
	c.OpenVPNAuthFile = filepath.Join(profileDir, "auth.txt")
	c.OpenVPNService = openVPNServiceName(c.Name)
	c.OpenVPNDevice = route.Device
	c.OpenVPNTable = route.Table
	c.OpenVPNMark = route.Mark
	c.OpenVPNPriority = route.Priority
	c.OpenVPNProvider = "VPN Gate (free public relay)"
	c.OpenVPNCountry = ""
	c.OpenVPNServer = ""
	c.OpenVPNServerIP = ""
	cleanupRoutePolicy := func() {
		_ = exec.Command(openVPNRouteHelperPath, "remove", strconv.Itoa(route.Table), strconv.Itoa(route.Mark), strconv.Itoa(route.Priority)).Run()
	}
	rollbackAll := func() {
		_ = exec.Command("systemctl", "disable", "--now", c.OpenVPNService).Run()
		cleanupRoutePolicy()
		_ = os.Remove(unitPath)
		rollbackCapabilities()
		rollbackDir()
		_ = systemdReload()
	}

	// A first successful candidate is retained. For failed or stale public
	// volunteers, the same isolated service is retried with the next candidate.
	unitInstalled := false
	for index, candidate := range candidates {
		sourcePath := filepath.Join(profileDir, fmt.Sprintf("candidate-%02d.ovpn", index+1))
		if err := os.WriteFile(sourcePath, candidate.Config, 0600); err != nil {
			rollbackAll()
			return fmt.Errorf("stage VPN Gate candidate %s: %w", candidate.IP, err)
		}
		if _, err := sanitizeOpenVPNProfile(sourcePath, managedConfig, authPath, c.Name, openVPNRouteHelperPath, route); err != nil {
			_ = os.Remove(sourcePath)
			uiWarn(fmt.Sprintf("Skipping incompatible VPN Gate relay %s: %v", candidate.IP, err))
			continue
		}
		_ = os.Remove(sourcePath)
		workDir := profileDir
		unit, err := renderOpenVPNUnit(c.Name, managedConfig, workDir, route, false)
		if err != nil {
			rollbackAll()
			return err
		}
		if !unitInstalled {
			if err := os.WriteFile(unitPath, unit, 0644); err != nil {
				rollbackAll()
				return err
			}
			if err := systemdReload(); err != nil {
				rollbackAll()
				return err
			}
			if out, err := exec.Command("systemctl", "enable", c.OpenVPNService).CombinedOutput(); err != nil {
				rollbackAll()
				return fmt.Errorf("enable isolated OpenVPN service: %w: %s", err, tailText(string(out), 1500))
			}
			unitInstalled = true
		}
		uiInfo("Trying VPN Gate relay " + vpnGateServerLabel(candidate))
		out, startErr := exec.Command("systemctl", "start", c.OpenVPNService).CombinedOutput()
		if startErr == nil {
			startErr = waitOpenVPNRoute(c, 35*time.Second)
		}
		var exitIP string
		if startErr == nil {
			exitIP, startErr = openVPNPublicEgressIP(c.OpenVPNMark, 10*time.Second)
		}
		if startErr == nil {
			// During candidate discovery, Restart=no ensures one bad public relay
			// cannot consume systemd's restart budget before we try the next one.
			// Once a relay has passed both route and egress-IP checks, install the
			// persistent restart policy and start it once under the final unit.
			finalUnit, unitErr := renderOpenVPNUnit(c.Name, managedConfig, workDir, route, true)
			if unitErr != nil {
				rollbackAll()
				return unitErr
			}
			if unitErr = exec.Command("systemctl", "stop", c.OpenVPNService).Run(); unitErr == nil {
				unitErr = os.WriteFile(unitPath, finalUnit, 0644)
			}
			if unitErr == nil {
				unitErr = systemdReload()
			}
			if unitErr == nil {
				_ = exec.Command("systemctl", "reset-failed", c.OpenVPNService).Run()
				unitErr = exec.Command("systemctl", "start", c.OpenVPNService).Run()
			}
			if unitErr == nil {
				unitErr = waitOpenVPNRoute(c, 35*time.Second)
			}
			if unitErr == nil {
				exitIP, unitErr = openVPNPublicEgressIP(c.OpenVPNMark, 10*time.Second)
			}
			if unitErr != nil {
				rollbackAll()
				return fmt.Errorf("VPN Gate relay passed initial validation but failed under its persistent service policy: %w", unitErr)
			}
			c.OpenVPNCountry = candidate.Country
			c.OpenVPNServer = candidate.HostName
			c.OpenVPNServerIP = candidate.IP
			if c.OpenVPNServer == "" {
				c.OpenVPNServer = candidate.IP
			}
			uiSuccess(fmt.Sprintf("Connected through free VPN Gate relay %s; verified public exit IP: %s", vpnGateServerLabel(candidate), exitIP))
			uiWarn("VPN Gate relays are operated by volunteers; speed and availability may change, and this network is not suitable for sensitive traffic.")
			return nil
		}
		journal, _ := exec.Command("journalctl", "-u", c.OpenVPNService, "-n", "12", "--no-pager", "-o", "cat").CombinedOutput()
		uiWarn(fmt.Sprintf("VPN Gate relay %s failed; trying the next candidate: %v %s %s", candidate.IP, startErr, tailText(string(out), 600), tailText(string(journal), 1200)))
		_ = exec.Command("systemctl", "stop", c.OpenVPNService).Run()
		_ = exec.Command("systemctl", "reset-failed", c.OpenVPNService).Run()
		_ = exec.Command(openVPNRouteHelperPath, "down", strconv.Itoa(route.Table), strconv.Itoa(route.Mark), strconv.Itoa(route.Priority)).Run()
	}
	rollbackAll()
	return errors.New("all tested VPN Gate TCP relays failed to establish a verified OpenVPN route; no Agent profile was saved and the dedicated policy route was rolled back")
}

func waitOpenVPNRoute(c *Config, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if verifyOpenVPNRoute(c) == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	journal, _ := exec.Command("journalctl", "-u", c.OpenVPNService, "-n", "35", "--no-pager", "-o", "cat").CombinedOutput()
	return fmt.Errorf("OpenVPN did not establish its isolated TUN route within %s; journal: %s", timeout, tailText(string(journal), 4000))
}

func verifyOpenVPNRoute(c *Config) error {
	if c == nil || c.OpenVPNTable == 0 || c.OpenVPNMark == 0 {
		return errors.New("OpenVPN routing metadata is incomplete")
	}
	out, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1", "mark", strconv.Itoa(c.OpenVPNMark)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect marked OpenVPN route: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if !strings.Contains(string(out), "dev "+c.OpenVPNDevice) {
		return fmt.Errorf("marked route is not using the dedicated OpenVPN TUN %s: %s", c.OpenVPNDevice, strings.TrimSpace(string(out)))
	}
	return nil
}

func openVPNPublicEgressIP(mark int, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Resolve the verification hostname through the marked VPN route as well;
	// the host's ordinary resolver must not be used for this egress check.
	resolver := &net.Resolver{PreferGo: true, Dial: func(dnsCtx context.Context, network, _ string) (net.Conn, error) {
		return dialMarkedContext(dnsCtx, network, net.JoinHostPort("1.1.1.1", "53"), mark)
	}}
	ips, err := resolver.LookupIP(ctx, "ip4", "api.ipify.org")
	if err != nil {
		return "", fmt.Errorf("resolve IP check endpoint through marked VPN egress: %w", err)
	}
	if len(ips) == 0 {
		return "", errors.New("IP check endpoint returned no IPv4 address")
	}
	ip := ips[0].String()
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "api.ipify.org"}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		return dialMarkedContext(ctx, network, net.JoinHostPort(ip, port), mark)
	}}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(ip, "443")+"/", nil)
	req.Host = "api.ipify.org"
	resp, err := (&http.Client{Transport: tr, Timeout: timeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("marked HTTPS egress check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IP check returned HTTP %s", resp.Status)
	}
	b := make([]byte, 128)
	n, _ := resp.Body.Read(b)
	result := strings.TrimSpace(string(b[:n]))
	parsed := net.ParseIP(result)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("IP check returned an invalid IPv4 value %q", result)
	}
	return result, nil
}

func dialMarkedContext(ctx context.Context, network, address string, mark int) (net.Conn, error) {
	if mark <= 0 || mark > 0x7fffffff {
		return nil, errors.New("invalid OpenVPN socket mark")
	}
	d := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second, Control: func(network, address string, raw syscall.RawConn) error {
		var setErr error
		if err := raw.Control(func(fd uintptr) { setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark) }); err != nil {
			return err
		}
		return setErr
	}}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("connect through OpenVPN policy route: %w", err)
	}
	return conn, nil
}

func startOpenVPNForAgent(c Config) (func(), error) {
	if strings.TrimSpace(c.OpenVPNConfig) == "" || c.OpenVPNService == "" {
		return nil, errors.New("OpenVPN profile is not configured")
	}
	if _, err := os.Stat(c.OpenVPNConfig); err != nil {
		return nil, fmt.Errorf("managed OpenVPN config missing: %w", err)
	}
	if err := exec.Command("systemctl", "enable", "--now", c.OpenVPNService).Run(); err != nil {
		return nil, fmt.Errorf("start OpenVPN service %s: %w", c.OpenVPNService, err)
	}
	if err := waitOpenVPNRoute(&c, 60*time.Second); err != nil {
		return nil, err
	}
	return func() {}, nil
}

func removeOpenVPNProfile(c *Config) error {
	if c == nil {
		return nil
	}
	if c.OpenVPNService != "" {
		out, err := exec.Command("systemctl", "disable", "--now", c.OpenVPNService).CombinedOutput()
		if err != nil {
			state, _ := exec.Command("systemctl", "show", c.OpenVPNService, "-p", "LoadState", "--value").Output()
			if strings.TrimSpace(string(state)) != "not-found" {
				return fmt.Errorf("stop OpenVPN service: %w: %s", err, tailText(string(out), 1500))
			}
		}
		unit := filepath.Join("/etc/systemd/system", c.OpenVPNService)
		if err := os.Remove(unit); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if c.OpenVPNTable > 0 && c.OpenVPNMark > 0 && c.OpenVPNPriority > 0 {
		_ = exec.Command(openVPNRouteHelperPath, "remove", strconv.Itoa(c.OpenVPNTable), strconv.Itoa(c.OpenVPNMark), strconv.Itoa(c.OpenVPNPriority)).Run()
	}
	if c.Name != "" {
		drop := filepath.Join("/etc/systemd/system", "ravanreverse@"+tunnelID(c.Name)+".service.d", "20-openvpn-mark.conf")
		_ = os.Remove(drop)
	}
	if c.Name != "" {
		_ = os.RemoveAll(openVPNProfileDir(c.Name))
	}
	if entries, err := os.ReadDir("/etc/ravanreverse/openvpn"); err == nil && len(entries) == 0 {
		_ = os.Remove(openVPNRouteHelperPath)
	}
	if err := systemdReload(); err != nil {
		return err
	}
	return nil
}
