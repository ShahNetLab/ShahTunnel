package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	warpGuardConfigPath = "/etc/shah-tunnel/warp-route-guard.json"
	warpGuardUnitPath   = "/etc/systemd/system/shah-tunnel-warp-ssh-bypass.service"
	warpGuardUnitName   = "shah-tunnel-warp-ssh-bypass.service"
	warpManagedPath     = "/etc/shah-tunnel/warp-device-managed"
	warpSOCKSAddress    = "127.0.0.1:40000"
	warpDirectMark      = 0x5348
	warpIPv4Table       = 42420
	warpIPv6Table       = 42421
	warpMarkRulePref    = 10
	warpPeerRulePref    = 11
)

type physicalDefaultRoute struct {
	Gateway string `json:"gateway,omitempty"`
	Device  string `json:"device"`
	Source  string `json:"source,omitempty"`
}

type warpGuardConfig struct {
	IPv4      *physicalDefaultRoute `json:"ipv4,omitempty"`
	IPv6      *physicalDefaultRoute `json:"ipv6,omitempty"`
	SSHPeers  []string              `json:"ssh_peers,omitempty"`
	SSHPorts  []int                 `json:"ssh_ports,omitempty"`
	CreatedAt time.Time             `json:"created_at"`
}

func runOutput(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func parsePhysicalDefaultRoute(family string, output string) (*physicalDefaultRoute, error) {
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		r := &physicalDefaultRoute{}
		for i := 1; i < len(f); i++ {
			switch f[i] {
			case "via":
				if i+1 < len(f) {
					r.Gateway = strings.Trim(f[i+1], "[]")
					i++
				}
			case "dev":
				if i+1 < len(f) {
					r.Device = f[i+1]
					i++
				}
			case "src":
				if i+1 < len(f) {
					r.Source = f[i+1]
					i++
				}
			}
		}
		if r.Device == "" {
			continue
		}
		low := strings.ToLower(r.Device)
		virtual := false
		for _, bad := range []string{"warp", "wg", "tun", "tap", "ppp", "tailscale", "zerotier", "utun", "clash", "sing"} {
			if strings.Contains(low, bad) {
				virtual = true
				break
			}
		}
		if virtual {
			continue
		}
		if strings.ContainsAny(r.Device, " \t\r\n/\\") {
			continue
		}
		if r.Gateway != "" {
			ip := net.ParseIP(r.Gateway)
			if ip == nil || (family == "-4" && ip.To4() == nil) || (family == "-6" && ip.To4() != nil) {
				continue
			}
		}
		if r.Source != "" {
			ip := net.ParseIP(r.Source)
			if ip == nil || (family == "-4" && ip.To4() == nil) || (family == "-6" && ip.To4() != nil) {
				continue
			}
		}
		return r, nil
	}
	return nil, fmt.Errorf("no physical %s default route found; refusing to enable full-device WARP without an SSH bypass", family)
}

func discoverPhysicalDefaultRoute(family string) (*physicalDefaultRoute, error) {
	ip, err := exec.LookPath("ip")
	if err != nil {
		return nil, errors.New("iproute2 is required for safe WARP routing")
	}
	out, err := runOutput(5*time.Second, ip, family, "route", "show", "default", "table", "main")
	if err != nil {
		return nil, err
	}
	return parsePhysicalDefaultRoute(family, out)
}

func currentSSHPeers() []string {
	seen := map[string]bool{}
	var peers []string
	add := func(s string) {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return
		}
		v := ip.String()
		if !seen[v] {
			seen[v] = true
			peers = append(peers, v)
		}
	}
	if env := strings.Fields(os.Getenv("SSH_CONNECTION")); len(env) >= 4 {
		add(env[0])
	}
	// Capture currently established SSH peers as a second source. This is
	// read-only and supports sessions started by systemd/socket activation.
	if ss, err := exec.LookPath("ss"); err == nil {
		if out, err := runOutput(5*time.Second, ss, "-Htnp", "state", "established"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) < 5 || !strings.Contains(line, "sshd") {
					continue
				}
				host, _, e := net.SplitHostPort(strings.Trim(f[4], "[]"))
				if e != nil {
					// ss formats IPv6 as [address]:port; SplitHostPort needs brackets.
					host, _, e = net.SplitHostPort(f[4])
				}
				if e == nil {
					add(host)
				}
			}
		}
	}
	return peers
}

func currentSSHPorts() []int {
	seen := map[int]bool{}
	var ports []int
	add := func(v string) {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil && n > 0 && n <= 65535 && !seen[n] {
			seen[n] = true
			ports = append(ports, n)
		}
	}
	if sshd, err := exec.LookPath("sshd"); err == nil {
		if out, err := runOutput(5*time.Second, sshd, "-T"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				f := strings.Fields(line)
				if len(f) >= 2 && f[0] == "port" {
					add(f[1])
				}
			}
		}
	}
	if env := strings.Fields(os.Getenv("SSH_CONNECTION")); len(env) >= 4 {
		add(env[3])
	}
	if len(ports) == 0 {
		add("22")
	}
	return ports
}

func ensureNFTables() error {
	if _, err := exec.LookPath("nft"); err == nil {
		return nil
	}
	apt, err := exec.LookPath("apt-get")
	if err != nil {
		return errors.New("nftables is required to protect SSH during full-device WARP; install nftables and retry")
	}
	uiInfo("Installing the nftables firewall helper required to keep SSH outside WARP.")
	if _, err := runOutput(90*time.Second, apt, "-o", "Acquire::http::Timeout=20", "-o", "Acquire::https::Timeout=20", "-o", "Acquire::Retries=1", "install", "-y", "nftables"); err != nil {
		return fmt.Errorf("could not install nftables; WARP device mode was not enabled: %w", err)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("nftables package was installed but nft command is unavailable")
	}
	return nil
}

func discoverWarpGuardConfig() (warpGuardConfig, error) {
	var cfg warpGuardConfig
	v4, err := discoverPhysicalDefaultRoute("-4")
	if err != nil {
		return cfg, err
	}
	cfg.IPv4 = v4
	if v6, e := discoverPhysicalDefaultRoute("-6"); e == nil {
		cfg.IPv6 = v6
	}
	cfg.SSHPeers = currentSSHPeers()
	cfg.SSHPorts = currentSSHPorts()
	for _, peer := range cfg.SSHPeers {
		if ip := net.ParseIP(peer); ip != nil && ip.To4() == nil && cfg.IPv6 == nil {
			return cfg, errors.New("an active SSH session uses IPv6 but no physical IPv6 default route was found; refusing full-device WARP")
		}
	}
	if len(cfg.SSHPeers) == 0 && len(cfg.SSHPorts) == 0 {
		return cfg, errors.New("could not identify the SSH session or SSH listening port; refusing to enable full-device WARP")
	}
	cfg.CreatedAt = time.Now().UTC()
	return cfg, nil
}

// missingFIBTableOutput recognizes the one non-zero exit that is expected
// before Shah Tunnel creates its private route tables. iproute2 returns exit
// status 2 (rather than an empty result) when a numeric FIB table has never
// been instantiated. Do not suppress unrelated iproute2/netlink failures.
func missingFIBTableOutput(family, output string) bool {
	familyName := ""
	switch family {
	case "-4":
		familyName = "ipv4"
	case "-6":
		familyName = "ipv6"
	default:
		return false
	}
	return strings.Contains(strings.ToLower(output), familyName+": fib table does not exist")
}

// showPhysicalRouteTable returns an empty table for a never-created FIB while
// preserving every other command failure. This allows the first route replace
// to instantiate the table naturally, without adding temporary policy rules or
// touching the host's main/default routes.
func showPhysicalRouteTable(ip, family string, table int) (string, error) {
	tableText := strconv.Itoa(table)
	out, err := runOutput(5*time.Second, ip, family, "route", "show", "table", tableText)
	if err == nil {
		return out, nil
	}
	if missingFIBTableOutput(family, out) {
		return "", nil
	}
	return "", err
}

// policyRuleUsesTable detects an existing RPDB rule that already refers to a
// private table. An empty/uncreated FIB can still be owned by another service
// through a policy rule, so it must not be claimed by Shah Tunnel.
func policyRuleUsesTable(rules string, table int) bool {
	wanted := strconv.Itoa(table)
	for _, line := range strings.Split(rules, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if (fields[i] == "lookup" || fields[i] == "table") && fields[i+1] == wanted {
				return true
			}
		}
	}
	return false
}

func ensurePrivateWarpRouteTablesAvailable() error {
	ip, err := exec.LookPath("ip")
	if err != nil {
		return errors.New("iproute2 is required for safe WARP routing")
	}
	for _, item := range []struct {
		family string
		table  int
	}{{"-4", warpIPv4Table}, {"-6", warpIPv6Table}} {
		out, err := showPhysicalRouteTable(ip, item.family, item.table)
		if err != nil {
			return fmt.Errorf("inspect dedicated physical-route table %d: %w", item.table, err)
		}
		if strings.TrimSpace(out) != "" {
			return fmt.Errorf("routing table %d is already in use; refusing to overwrite routes owned by another service", item.table)
		}
		out, err = runOutput(5*time.Second, ip, item.family, "rule", "show")
		if err != nil {
			return fmt.Errorf("inspect %s policy rules: %w", item.family, err)
		}
		if policyRuleUsesTable(out, item.table) {
			return fmt.Errorf("policy rules already reference dedicated physical-route table %d for %s; refusing to claim a table used by another service", item.table, item.family)
		}
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 0 {
				continue
			}
			priority := strings.TrimSuffix(f[0], ":")
			if priority == strconv.Itoa(warpMarkRulePref) || priority == strconv.Itoa(warpPeerRulePref) {
				return fmt.Errorf("policy rule priority %s is already occupied for %s; refusing to change existing routing policy", priority, item.family)
			}
		}
	}
	return nil
}

func ensureWarpSSHGuard() error {
	if err := ensureNFTables(); err != nil {
		return err
	}
	var cfg warpGuardConfig
	if b, err := os.ReadFile(warpGuardConfigPath); err == nil {
		if json.Unmarshal(b, &cfg) != nil || cfg.IPv4 == nil || cfg.IPv4.Device == "" {
			return errors.New("existing WARP SSH guard file is invalid; refusing to change routes")
		}
		for _, p := range currentSSHPeers() {
			found := false
			for _, old := range cfg.SSHPeers {
				if old == p {
					found = true
				}
			}
			if !found {
				cfg.SSHPeers = append(cfg.SSHPeers, p)
			}
		}
		for _, p := range currentSSHPorts() {
			found := false
			for _, old := range cfg.SSHPorts {
				if old == p {
					found = true
				}
			}
			if !found {
				cfg.SSHPorts = append(cfg.SSHPorts, p)
			}
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := ensurePrivateWarpRouteTablesAvailable(); err != nil {
			return err
		}
		var discoverErr error
		cfg, discoverErr = discoverWarpGuardConfig()
		if discoverErr != nil {
			return discoverErr
		}
	} else {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(warpGuardConfigPath, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("write WARP SSH guard config: %w", err)
	}
	unit := `[Unit]
Description=Shah Tunnel physical-route guard for SSH and direct fallback transports
Wants=network-online.target
After=network-online.target
Before=warp-svc.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/ravanreverse warp-ssh-guard install
TimeoutStartSec=20
TimeoutStopSec=10
[Install]
WantedBy=multi-user.target
`
	if err := atomicWriteFile(warpGuardUnitPath, []byte(unit), 0644); err != nil {
		return fmt.Errorf("write WARP SSH guard unit: %w", err)
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemd daemon-reload for SSH guard: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "enable", warpGuardUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("could not enable SSH route guard; WARP was not enabled: %w: %s", err, strings.TrimSpace(string(out)))
	}
	action := "start"
	if exec.Command("systemctl", "is-active", "--quiet", warpGuardUnitName).Run() == nil {
		action = "restart"
	}
	if out, err := exec.Command("systemctl", action, warpGuardUnitName).CombinedOutput(); err != nil {
		return fmt.Errorf("could not %s SSH route guard; WARP was not enabled: %w: %s", action, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func applyPhysicalRoute(family string, route *physicalDefaultRoute, table int) error {
	if route == nil {
		return nil
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	tableText := strconv.Itoa(table)
	existing, err := showPhysicalRouteTable(ip, family, table)
	if err != nil {
		return fmt.Errorf("inspect physical-route table %s: %w", tableText, err)
	}
	if strings.TrimSpace(existing) != "" {
		lines := 0
		for _, line := range strings.Split(existing, "\n") {
			if strings.TrimSpace(line) != "" {
				lines++
			}
		}
		current, parseErr := parsePhysicalDefaultRoute(family, existing)
		if lines != 1 || parseErr != nil || current.Device != route.Device || current.Gateway != route.Gateway || current.Source != route.Source {
			return fmt.Errorf("routing table %s is no longer the Shah Tunnel physical-route table; refusing to replace or delete routes owned by another service", tableText)
		}
		return nil
	}
	args := []string{family, "route", "replace", "default"}
	if route.Gateway != "" {
		args = append(args, "via", route.Gateway)
	}
	args = append(args, "dev", route.Device)
	if route.Source != "" {
		args = append(args, "src", route.Source)
	}
	args = append(args, "table", tableText)
	if out, err := exec.Command(ip, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("restore physical %s route: %w: %s", family, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// policyFieldsContain searches the complete ip rule token list. Some iproute2
// versions append fwmark/lookup fields after several other tokens; returning
// false at the first unrelated token breaks idempotent guard restarts.
func policyFieldsContain(fields []string, key, value string) bool {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] != key {
			continue
		}
		got, want := fields[i+1], value
		if key == "fwmark" {
			got = strings.TrimSuffix(got, "/0xffffffff")
			want = strings.TrimSuffix(want, "/0xffffffff")
		}
		if got == want {
			return true
		}
	}
	return false
}

func addIPRule(family string, args ...string) error {
	ip, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	full := append([]string{family, "rule", "add"}, args...)
	out, err := exec.Command(ip, full...).CombinedOutput()
	if err == nil {
		return nil
	}
	if !strings.Contains(strings.ToLower(string(out)), "file exists") {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	// An idempotent duplicate is acceptable only when the exact rule already
	// exists. Do not silently accept a different service's rule at this pref.
	show, showErr := runOutput(5*time.Second, ip, family, "rule", "show")
	if showErr != nil {
		return fmt.Errorf("could not verify an existing policy rule: %w", showErr)
	}
	priority, lookup, matchKind, matchValue := "", "", "", ""
	for i := 0; i+1 < len(args); i++ {
		switch args[i] {
		case "priority":
			priority = args[i+1]
		case "lookup":
			lookup = args[i+1]
		case "fwmark", "to":
			matchKind, matchValue = args[i], args[i+1]
		}
	}
	for _, line := range strings.Split(show, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 2 || strings.TrimSuffix(f[0], ":") != priority {
			continue
		}
		if policyFieldsContain(f, "lookup", lookup) && matchKind != "" && policyFieldsContain(f, matchKind, matchValue) {
			return nil
		}
	}
	return fmt.Errorf("policy rule priority %s is already occupied by a different rule; refusing to reuse it", priority)
}

func installWarpSSHGuard() error {
	b, err := os.ReadFile(warpGuardConfigPath)
	if err != nil {
		return fmt.Errorf("WARP route guard config is missing: %w", err)
	}
	var cfg warpGuardConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("decode WARP route guard config: %w", err)
	}
	if cfg.IPv4 == nil || cfg.IPv4.Device == "" {
		return errors.New("physical IPv4 route was not recorded; refusing WARP startup")
	}
	if err := applyPhysicalRoute("-4", cfg.IPv4, warpIPv4Table); err != nil {
		return err
	}
	if cfg.IPv6 != nil {
		if err := applyPhysicalRoute("-6", cfg.IPv6, warpIPv6Table); err != nil {
			return err
		}
	}
	if err := addIPRule("-4", "priority", strconv.Itoa(warpMarkRulePref), "fwmark", fmt.Sprintf("0x%x/0xffffffff", warpDirectMark), "lookup", strconv.Itoa(warpIPv4Table)); err != nil {
		return err
	}
	if cfg.IPv6 != nil {
		if err := addIPRule("-6", "priority", strconv.Itoa(warpMarkRulePref), "fwmark", fmt.Sprintf("0x%x/0xffffffff", warpDirectMark), "lookup", strconv.Itoa(warpIPv6Table)); err != nil {
			return err
		}
	}
	for _, peer := range cfg.SSHPeers {
		ip := net.ParseIP(peer)
		if ip == nil {
			continue
		}
		family, prefix := "-4", "/32"
		if ip.To4() == nil {
			family, prefix = "-6", "/128"
			if cfg.IPv6 == nil {
				continue
			}
		}
		_ = addIPRule(family, "priority", strconv.Itoa(warpPeerRulePref), "to", peer+prefix, "lookup", map[bool]string{true: strconv.Itoa(warpIPv6Table), false: strconv.Itoa(warpIPv4Table)}[family == "-6"])
	}
	if err := installNFTSSHMarks(cfg.SSHPorts); err != nil {
		return err
	}
	return nil
}

func installNFTSSHMarks(ports []int) error {
	nft, err := exec.LookPath("nft")
	if err != nil {
		return errors.New("nft command is required to mark SSH replies for the direct route")
	}
	if _, err := exec.Command(nft, "list", "table", "inet", "shah_tunnel_warp_guard").CombinedOutput(); err != nil {
		if out, addErr := exec.Command(nft, "add", "table", "inet", "shah_tunnel_warp_guard").CombinedOutput(); addErr != nil {
			return fmt.Errorf("create nftables SSH guard table: %w: %s", addErr, strings.TrimSpace(string(out)))
		}
	}
	chainArgs := []string{"add", "chain", "inet", "shah_tunnel_warp_guard", "output", "{", "type", "route", "hook", "output", "priority", "mangle", ";", "policy", "accept", ";", "}"}
	if _, err := exec.Command(nft, "list", "chain", "inet", "shah_tunnel_warp_guard", "output").CombinedOutput(); err != nil {
		if out, addErr := exec.Command(nft, chainArgs...).CombinedOutput(); addErr != nil {
			return fmt.Errorf("create nftables SSH guard chain: %w: %s", addErr, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.Command(nft, "flush", "chain", "inet", "shah_tunnel_warp_guard", "output").CombinedOutput(); err != nil {
		return fmt.Errorf("flush owned nftables SSH guard chain: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			continue
		}
		args := []string{"add", "rule", "inet", "shah_tunnel_warp_guard", "output", "tcp", "sport", strconv.Itoa(port), "meta", "mark", "set", fmt.Sprintf("0x%x", warpDirectMark)}
		if out, err := exec.Command(nft, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("add nftables SSH route mark for port %d: %w: %s", port, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func removeOwnedPhysicalRouteTable(family string, route *physicalDefaultRoute, table int) error {
	if route == nil {
		return nil
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	tableText := strconv.Itoa(table)
	out, err := showPhysicalRouteTable(ip, family, table)
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}
	lines := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	current, parseErr := parsePhysicalDefaultRoute(family, out)
	if lines != 1 || parseErr != nil || current.Device != route.Device || current.Gateway != route.Gateway || current.Source != route.Source {
		return fmt.Errorf("routing table %s contains routes not owned by Shah Tunnel; leaving that table untouched", tableText)
	}
	if result, flushErr := exec.Command(ip, family, "route", "flush", "table", tableText).CombinedOutput(); flushErr != nil {
		return fmt.Errorf("flush Shah Tunnel physical-route table %s: %w: %s", tableText, flushErr, strings.TrimSpace(string(result)))
	}
	return nil
}

func removeWarpSSHGuard() error {
	var first error
	var cfg warpGuardConfig
	cfgLoaded := false
	if b, err := os.ReadFile(warpGuardConfigPath); err == nil {
		if json.Unmarshal(b, &cfg) == nil {
			cfgLoaded = true
		} else {
			first = errors.New("WARP SSH guard config is invalid; preserving it and its route tables")
		}
	}
	if nft, err := exec.LookPath("nft"); err == nil {
		if out, e := exec.Command(nft, "delete", "table", "inet", "shah_tunnel_warp_guard").CombinedOutput(); e != nil && !strings.Contains(strings.ToLower(string(out)), "no such file") && first == nil {
			first = fmt.Errorf("delete owned nftables guard table: %w: %s", e, strings.TrimSpace(string(out)))
		}
	}
	ip, _ := exec.LookPath("ip")
	if ip != "" {
		for _, family := range []string{"-4", "-6"} {
			table := warpIPv4Table
			if family == "-6" {
				table = warpIPv6Table
			}
			_, _ = exec.Command(ip, family, "rule", "del", "priority", strconv.Itoa(warpMarkRulePref), "fwmark", fmt.Sprintf("0x%x/0xffffffff", warpDirectMark), "lookup", strconv.Itoa(table)).CombinedOutput()
		}
		if cfgLoaded {
			for _, peer := range cfg.SSHPeers {
				addr := net.ParseIP(peer)
				family, prefix, table := "-4", "/32", warpIPv4Table
				if addr != nil && addr.To4() == nil {
					family, prefix, table = "-6", "/128", warpIPv6Table
				}
				_, _ = exec.Command(ip, family, "rule", "del", "priority", strconv.Itoa(warpPeerRulePref), "to", peer+prefix, "lookup", strconv.Itoa(table)).CombinedOutput()
			}
			if err := removeOwnedPhysicalRouteTable("-4", cfg.IPv4, warpIPv4Table); err != nil && first == nil {
				first = err
			}
			if err := removeOwnedPhysicalRouteTable("-6", cfg.IPv6, warpIPv6Table); err != nil && first == nil {
				first = err
			}
		}
	}
	if first != nil {
		return first
	}
	_ = os.Remove(warpGuardConfigPath)
	_ = os.Remove(warpManagedPath)
	return nil
}

func runWarpSSHGuardCommand(action string) error {
	switch action {
	case "install":
		return installWarpSSHGuard()
	case "remove":
		return removeWarpSSHGuard()
	default:
		return fmt.Errorf("unknown WARP SSH guard action %q", action)
	}
}

func ensureCloudflareWarpRegistered(interactive bool) error {
	if _, err := exec.LookPath("warp-cli"); err != nil {
		return errors.New("Cloudflare WARP is not installed; install it before selecting the WARP path")
	}
	if out, err := exec.Command("systemctl", "enable", "--now", "warp-svc").CombinedOutput(); err != nil {
		return fmt.Errorf("could not enable/start warp-svc: %w: %s", err, strings.TrimSpace(string(out)))
	}
	regOut, regErr := runWarpCLI("registration", "show")
	regText := strings.ToLower(regOut)
	registered := strings.Contains(regText, "account type") || strings.Contains(regText, "device id") || strings.Contains(regText, "registration id")
	missing := strings.Contains(regText, "registration missing") || strings.Contains(regText, "missing registration") || strings.Contains(regText, "not registered") || strings.Contains(regText, "does not exist") || strings.Contains(regText, "no registration")
	if missing {
		if !interactive || !wizardYesNo("Accept Cloudflare Terms of Service and Privacy Policy and register this server? (y/N)", "n") {
			return errors.New("Cloudflare WARP registration is required; no WARP route was changed")
		}
		if _, err := runWarpCLI("registration", "new"); err != nil {
			return fmt.Errorf("Cloudflare WARP registration failed: %w", err)
		}
	} else if regErr != nil {
		return fmt.Errorf("could not inspect the existing Cloudflare registration; leaving it unchanged: %w", regErr)
	} else if !registered {
		return fmt.Errorf("Cloudflare registration status was not recognized; leaving it unchanged: %s", strings.TrimSpace(regOut))
	}
	return nil
}

func warpSettings() string {
	out, _ := runWarpCLI("settings")
	return out
}

func warpIsProxyMode() bool {
	return strings.Contains(strings.ToLower(warpSettings()), "warpproxy")
}

func warpSettingsIsDeviceMode(settings string) bool {
	low := strings.ToLower(settings)
	if strings.Contains(low, "warpproxy") {
		return false
	}
	return strings.Contains(low, "mode: warp")
}

func warpNeedsProxyRestore() bool {
	// Only change WARP state automatically when this application explicitly
	// marked the full-device session as its own. User-managed WARP settings are
	// never rewritten as a side effect of stopping a tunnel or uninstalling.
	_, err := os.Stat(warpManagedPath)
	return err == nil
}

func verifyCloudflareWarpDeviceEgress() error {
	curl, err := exec.LookPath("curl")
	if err != nil {
		return errors.New("curl is required to verify WARP full-device egress")
	}
	for _, family := range []string{"-4", "-6"} {
		ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
		args := []string{"--fail", "--silent", "--show-error", "--max-time", "18", "--noproxy", "*", family, "https://www.cloudflare.com/cdn-cgi/trace"}
		out, runErr := exec.CommandContext(ctx, curl, args...).CombinedOutput()
		cancel()
		if runErr != nil {
			return fmt.Errorf("WARP %s egress check failed: %w: %s", family, runErr, strings.TrimSpace(string(out)))
		}
		trace := strings.ToLower(string(out))
		if !strings.Contains(trace, "warp=on") && !strings.Contains(trace, "warp=plus") {
			return fmt.Errorf("Cloudflare %s trace did not confirm WARP egress: %s", family, strings.TrimSpace(string(out)))
		}
		if family == "-4" {
			uiSuccess("IPv4 internet egress is confirmed through Cloudflare WARP.")
		} else {
			uiSuccess("IPv6 internet egress is confirmed through Cloudflare WARP.")
		}
	}
	return nil
}

func rollbackCloudflareWarpDevice(cause error) error {
	if rollbackErr := configureCloudflareWarpProxyMode(); rollbackErr != nil {
		return fmt.Errorf("%w; automatic rollback to Local Proxy mode also failed: %v; the SSH physical-route guard has been left installed", cause, rollbackErr)
	}
	return fmt.Errorf("%w; WARP was returned to Local Proxy mode and the SSH physical-route guard was kept", cause)
}

func configureCloudflareWarpDevice(interactive bool) error {
	if _, err := exec.LookPath("warp-cli"); err != nil {
		return errors.New("Cloudflare WARP is not installed; install the official WARP package before selecting this path")
	}
	// Install SSH's physical-route protection BEFORE starting warp-svc. A saved
	// Always-On device-WARP profile can connect as soon as the daemon starts.
	if err := ensureWarpSSHGuard(); err != nil {
		return fmt.Errorf("SSH protection could not be installed; WARP service was not started or reconfigured: %w", err)
	}
	if err := ensureCloudflareWarpRegistered(interactive); err != nil {
		return err
	}
	// If a previous Shah Tunnel start already enabled and verified device WARP,
	// do not disconnect it: that would interrupt all 12 authenticated lanes.
	if !warpIsProxyMode() && warpStatusConnected() {
		if err := verifyCloudflareWarpDeviceEgress(); err == nil {
			_ = atomicWriteFile(warpManagedPath, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0600)
			return nil
		}
	}
	uiWarn("Device WARP routes unmarked outbound traffic from this VPS through Cloudflare while option 8/9 WARP is active. SSH replies and direct fallback tunnel sockets are routed over the physical VPS link.")
	// The physical routes and SSH marks are active before changing WARP mode.
	_, _ = runWarpCLI("disconnect")
	if _, err := runWarpCLI("mode", "warp+doh"); err != nil {
		if _, fallbackErr := runWarpCLI("mode", "warp"); fallbackErr != nil {
			return rollbackCloudflareWarpDevice(fmt.Errorf("could not switch WARP to full-device mode: %v; fallback also failed: %w", err, fallbackErr))
		}
	}
	if _, err := runWarpCLI("tunnel", "protocol", "set", "MASQUE"); err != nil {
		return rollbackCloudflareWarpDevice(fmt.Errorf("could not set MASQUE protocol: %w", err))
	}
	if _, err := runWarpCLI("connect"); err != nil {
		return rollbackCloudflareWarpDevice(fmt.Errorf("could not connect Cloudflare WARP: %w", err))
	}
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		status, _ := runWarpCLI("status")
		if warpStatusOutputConnected(status) && !warpIsProxyMode() {
			if err := verifyCloudflareWarpDeviceEgress(); err != nil {
				return rollbackCloudflareWarpDevice(err)
			}
			_ = atomicWriteFile(warpManagedPath, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0600)
			uiSuccess("Full-device WARP is active; SSH replies and direct fallback sockets have a physical-route bypass.")
			return nil
		}
		time.Sleep(700 * time.Millisecond)
	}
	return rollbackCloudflareWarpDevice(errors.New("Cloudflare WARP did not reach full-device Connected mode within 35 seconds; route profile was not accepted"))
}

// configureCloudflareWarpProxyMode keeps Cloudflare WARP in Local Proxy mode.
// It never enables device-level routing. When migrating a connected legacy
// device-mode client, the physical SSH guard is installed before disconnecting
// the global route. The resulting SOCKS5 listener is shared safely by profiles;
// each Agent only uses it for its own Hub carrier sockets.
func configureCloudflareWarpProxyMode() error {
	return configureCloudflareWarpProxyModeWithInteraction(false)
}

func configureCloudflareWarpProxyModeInteractive() error {
	return configureCloudflareWarpProxyModeWithInteraction(true)
}

func configureCloudflareWarpProxyModeWithInteraction(interactive bool) error {
	if _, err := exec.LookPath("warp-cli"); err != nil {
		return errors.New("Cloudflare WARP is not installed")
	}

	// Inspect the currently configured mode before making any change. A
	// connected device-mode WARP session changes host-wide routing, so only an
	// interactive operator who explicitly approves may convert it to Local
	// Proxy. This conversion disconnects the global route first; no policy
	// routing table or SSH guard is created for a profile-scoped SOCKS path.
	settings := warpSettings()
	status, statusErr := runWarpCLI("status")
	connected := statusErr == nil && warpStatusOutputConnected(status)
	deviceMode := warpSettingsIsDeviceMode(settings)
	approvedDeviceModeSwitch := false
	serviceActive := exec.Command("systemctl", "is-active", "--quiet", "warp-svc.service").Run() == nil
	if deviceMode && !interactive {
		return errors.New("Cloudflare WARP is configured in full-device mode. Open the Shah Tunnel menu and select the WARP path interactively to approve switching it to Local Proxy; no routes or WARP settings were changed")
	}
	if !serviceActive && strings.TrimSpace(settings) == "" && !interactive {
		return errors.New("WARP mode cannot be verified while warp-svc is stopped. Run the Agent WARP setup interactively once; Shah Tunnel will not start an unknown device-wide WARP profile at boot")
	}
	if deviceMode && connected {
		if !wizardYesNo("Cloudflare WARP is currently changing the entire VPS route. Switch it to Local Proxy so only this Agent's Hub connections use WARP? Other VPS applications will return to the normal direct route. Continue? (y/N)", "n") {
			return errors.New("operator declined switching full-device WARP to Local Proxy; existing WARP routing was left unchanged")
		}
		approvedDeviceModeSwitch = true
	}

	if err := ensureCloudflareWarpRegistered(interactive); err != nil {
		// A missing registration with no connected session is harmless: do not
		// register a device implicitly from a systemd restart.
		status, _ := runWarpCLI("status")
		if strings.Contains(strings.ToLower(err.Error()), "registration is required") && !warpStatusOutputConnected(status) {
			return err
		}
		return fmt.Errorf("cannot prepare Cloudflare WARP Local Proxy mode: %w", err)
	}

	settings = warpSettings()
	status, statusErr = runWarpCLI("status")
	connected = statusErr == nil && warpStatusOutputConnected(status)
	if warpSettingsIsDeviceMode(settings) {
		if connected {
			// The second read catches an Always-On device profile that may have
			// auto-connected when warp-svc started. Never silently take its route.
			if !approvedDeviceModeSwitch {
				if !interactive || !wizardYesNo("WARP auto-connected in full-device mode. Disconnect the VPS-wide route and continue with per-profile Local Proxy? (y/N)", "n") {
					return errors.New("WARP remains in full-device mode; no route was changed by Shah Tunnel")
				}
				approvedDeviceModeSwitch = true
			}
			if _, err := runWarpCLI("disconnect"); err != nil {
				return fmt.Errorf("could not disconnect full-device WARP before Local Proxy conversion: %w", err)
			}
		}
		if _, err := runWarpCLI("mode", "proxy"); err != nil {
			return fmt.Errorf("could not set Cloudflare WARP Local Proxy mode: %w", err)
		}
	} else if !strings.Contains(strings.ToLower(settings), "warpproxy") {
		return fmt.Errorf("Cloudflare WARP mode could not be verified; settings were left unchanged: %s", strings.TrimSpace(settings))
	}

	if _, err := runWarpCLI("proxy", "port", "40000"); err != nil {
		return fmt.Errorf("could not set WARP SOCKS5 proxy port 40000: %w", err)
	}
	if _, err := runWarpCLI("tunnel", "protocol", "set", "MASQUE"); err != nil {
		return fmt.Errorf("could not set WARP tunnel protocol to MASQUE: %w", err)
	}
	if !warpStatusConnected() {
		if _, err := runWarpCLI("connect"); err != nil {
			return fmt.Errorf("could not connect WARP Local Proxy: %w", err)
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if warpStatusConnected() && warpIsProxyMode() {
			if err := verifySOCKS5ProxyHandshake(warpSOCKSAddress, "", ""); err == nil {
				_ = os.Remove(warpManagedPath)
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("Cloudflare WARP did not expose a healthy SOCKS5 listener at %s in Local Proxy mode", warpSOCKSAddress)
}

func configRequiresCloudflareWarp(c Config) bool {
	if c.Role != "agent" || (c.Transport != transportNewMethods && c.Transport != transportFullAdaptive) {
		return false
	}
	for _, p := range c.ExternalPaths {
		if strings.EqualFold(strings.TrimSpace(p.Method), "warp") {
			if c.Transport == transportFullAdaptive || p.ID == c.SelectedExternalPath {
				return true
			}
		}
	}
	return false
}

func prepareAgentNetwork(c Config) error {
	if c.Role != "agent" {
		return nil
	}
	if configRequiresCloudflareWarp(c) {
		return configureCloudflareWarpProxyMode()
	}
	// Do not change WARP state for native/Tor/Psiphon/etc. profiles. Older
	// device-mode sessions are detected by compatibility checks and require
	// an explicit migration rather than a hidden global route change.
	return nil
}

func releaseManagedWarpIfUnused(skipConfigPath string) error {
	profiles, err := listTunnelProfiles()
	if err != nil {
		return err
	}
	for _, p := range profiles {
		if filepath.Clean(p.Path) == filepath.Clean(skipConfigPath) {
			continue
		}
		if exec.Command("systemctl", "is-active", "--quiet", p.Service).Run() != nil {
			continue
		}
		b, readErr := os.ReadFile(p.Path)
		if readErr != nil {
			continue
		}
		var other Config
		if json.Unmarshal(b, &other) == nil && configRequiresCloudflareWarp(normalizeConfig(other)) {
			return nil
		}
	}
	_, warpErr := exec.LookPath("warp-cli")
	if warpErr == nil && warpNeedsProxyRestore() {
		return configureCloudflareWarpProxyMode()
	}
	return nil
}

func directRouteControl() func(string, string, syscall.RawConn) error {
	if _, err := os.Stat(warpGuardConfigPath); err != nil {
		return nil
	}
	return func(network, address string, raw syscall.RawConn) error {
		// Do not claim a direct/physical bypass for an address family whose
		// physical default route was not captured. Failing closed is safer than
		// silently sending an IPv6 fallback through device WARP.
		if host, _, splitErr := net.SplitHostPort(address); splitErr == nil {
			if remoteIP := net.ParseIP(strings.Trim(host, "[]")); remoteIP != nil {
				guardBytes, readErr := os.ReadFile(warpGuardConfigPath)
				if readErr != nil {
					return fmt.Errorf("read physical-route guard: %w", readErr)
				}
				var guard warpGuardConfig
				if json.Unmarshal(guardBytes, &guard) != nil {
					return errors.New("physical-route guard is invalid; refusing direct fallback")
				}
				if remoteIP.To4() == nil && guard.IPv6 == nil {
					return errors.New("no physical IPv6 route was captured; refusing to send this direct fallback over WARP")
				}
				if remoteIP.To4() != nil && guard.IPv4 == nil {
					return errors.New("no physical IPv4 route was captured; refusing to send this direct fallback over WARP")
				}
			}
		}
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36 /* SO_MARK */, warpDirectMark)
		}); err != nil {
			return err
		}
		if socketErr != nil {
			return fmt.Errorf("mark direct fallback socket for physical VPS route: %w", socketErr)
		}
		return nil
	}
}

func makeDirectRouteDialer() net.Dialer {
	return net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second, Control: directRouteControl()}
}

func agentNetworkPreparation(c Config) error {
	return prepareAgentNetwork(c)
}

func warpStatusOutputConnected(out string) bool {
	for _, line := range strings.Split(strings.ToLower(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "status update:") && strings.TrimSpace(strings.TrimPrefix(line, "status update:")) == "connected" {
			return true
		}
	}
	return false
}

func warpStatusConnected() bool {
	out, err := runWarpCLI("status")
	return err == nil && warpStatusOutputConnected(out)
}

// agentNetworkPoliciesCompatible is always true for current Agent profiles:
// WARP is a SOCKS5 next-hop used by a profile's own Agent sockets, not a host
// default route. Old device-mode profiles are handled separately below.
func agentNetworkPoliciesCompatible(a, b Config) bool {
	return true
}

// legacyDeviceWarpConfig detects pre-2.2.8 profiles whose WARP path had no
// Address because it implicitly enabled full-device WARP. A live instance of
// such a profile must be restarted once on the new version before other
// profiles can safely share the machine.
func legacyDeviceWarpConfig(c Config) bool {
	if c.Role != "agent" {
		return false
	}
	for _, path := range c.ExternalPaths {
		if strings.EqualFold(strings.TrimSpace(path.Method), "warp") && strings.TrimSpace(path.Address) == "" {
			return true
		}
	}
	return false
}

func assertAgentProfileNetworkCompatibility(c Config) error {
	if c.Role != "agent" {
		return nil
	}
	profiles, err := listTunnelProfiles()
	if err != nil {
		return err
	}
	for _, p := range profiles {
		if filepath.Clean(p.Path) == filepath.Clean(configPath) {
			continue
		}
		if exec.Command("systemctl", "is-active", "--quiet", p.Service).Run() != nil {
			continue
		}
		b, readErr := os.ReadFile(p.Path)
		if readErr != nil {
			continue
		}
		var raw Config
		if json.Unmarshal(b, &raw) != nil || raw.Role != "agent" {
			continue
		}
		if legacyDeviceWarpConfig(raw) {
			return fmt.Errorf("Agent profile %q is still running an older full-device WARP mode. Restart that profile once with Shah Tunnel 2.2.8 first; the active service was not stopped or changed", p.Name)
		}
	}
	// A device-level WARP session not owned by a currently selected profile
	// would still capture unrelated app traffic. Never start a direct profile
	// under that global route; do not attempt to change a user's WARP settings.
	if !configRequiresCloudflareWarp(c) && warpStatusConnected() && warpSettingsIsDeviceMode(warpSettings()) {
		return errors.New("Cloudflare WARP is connected in full-device mode outside this profile. Disconnect or switch that external WARP client to Local Proxy mode before starting a direct Agent; Shah Tunnel will not change a global route")
	}
	return nil
}

func ensureAgentNetworkRuntime(c Config) error {
	if c.Role != "agent" {
		return nil
	}
	if err := assertAgentProfileNetworkCompatibility(c); err != nil {
		return err
	}
	if configRequiresCloudflareWarp(c) {
		if err := configureCloudflareWarpProxyMode(); err != nil {
			return fmt.Errorf("profile-scoped WARP SOCKS5 path is not ready: %w", err)
		}
		if err := verifySOCKS5ProxyHandshake(warpSOCKSAddress, "", ""); err != nil {
			return fmt.Errorf("WARP Local Proxy is not reachable at %s: %w", warpSOCKSAddress, err)
		}
	}
	return nil
}
