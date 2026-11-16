package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNewPsiphonClientConfigUsesAuthenticatedBootstrap(t *testing.T) {
	cfg := newPsiphonClientConfig(23456)
	if cfg.LocalSocksProxyPort != 23456 {
		t.Fatalf("SOCKS port = %d, want 23456", cfg.LocalSocksProxyPort)
	}
	if cfg.PropagationChannelID != psiphonPropagationChannelID || cfg.SponsorID != psiphonSponsorID || cfg.ClientVersion == "" {
		t.Fatal("Psiphon client identity fields must use the configured public client values")
	}
	if cfg.PropagationChannelID == "FFFFFFFFFFFFFFFF" || cfg.SponsorID == "FFFFFFFFFFFFFFFF" || cfg.SponsorID == "0000000000000000" {
		t.Fatal("placeholder Psiphon client identifiers must never be generated")
	}
	if cfg.RemoteServerListURL == "" || cfg.RemoteServerListSignaturePublicKey == "" || cfg.ServerEntrySignaturePublicKey == "" || cfg.ExchangeObfuscationKey == "" {
		t.Fatal("authenticated public server-list bootstrap is incomplete")
	}
	if key, err := base64.StdEncoding.DecodeString(cfg.ServerEntrySignaturePublicKey); err != nil || len(key) != 32 {
		t.Fatalf("server-entry signature key must decode to 32 bytes: len=%d err=%v", len(key), err)
	}
	if key, err := base64.StdEncoding.DecodeString(cfg.ExchangeObfuscationKey); err != nil || len(key) != 32 {
		t.Fatalf("exchange-obfuscation key must decode to 32 bytes: len=%d err=%v", len(key), err)
	}
	if key, err := base64.StdEncoding.DecodeString(cfg.RemoteServerListSignaturePublicKey); err != nil || len(key) < 256 {
		t.Fatalf("remote server-list signature key is malformed: len=%d err=%v", len(key), err)
	}
	if len(cfg.RemoteServerListURLs) < 2 || len(cfg.ObfuscatedServerListRootURLs) < 2 {
		t.Fatal("Psiphon bootstrap must include multiple public list mirrors")
	}
	for _, list := range [][]psiphonTransferURL{cfg.RemoteServerListURLs, cfg.ObfuscatedServerListRootURLs} {
		hasImmediate := false
		for _, item := range list {
			decoded, err := base64.StdEncoding.DecodeString(item.URL)
			if err != nil || !strings.HasPrefix(string(decoded), "https://") || item.SkipVerify {
				t.Fatalf("invalid authenticated Psiphon transfer URL: %+v", item)
			}
			if item.OnlyAfterAttempts == 0 {
				hasImmediate = true
			}
		}
		if !hasImmediate {
			t.Fatal("each Psiphon transfer list needs an immediate mirror")
		}
	}
	if !cfg.DisableLocalHTTPProxy || cfg.DisableLocalSocksProxy || cfg.UseUnixDomainSockets {
		t.Fatal("configuration must expose only a TCP loopback SOCKS5 proxy")
	}
	if !cfg.EmitDiagnosticNotices {
		t.Fatal("Psiphon diagnostic notices must be enabled so bootstrap/tunnel failures are observable")
	}
	if cfg.ConnectionWorkerPoolMaxSize != 0 {
		t.Fatalf("ConnectionWorkerPoolMaxSize=%d; expected the Psiphon default (unset)", cfg.ConnectionWorkerPoolMaxSize)
	}
	if cfg.SSHChannelWindowSize == nil || *cfg.SSHChannelWindowSize < 1 || *cfg.SSHChannelWindowSize > 128 {
		t.Fatalf("SSHChannelWindowSize=%v; want a valid Psiphon channel window", cfg.SSHChannelWindowSize)
	}
	// Exercise the same on-disk validator used by Agent startup, not a test-only
	// approximation of its checks.
	dir := t.TempDir()
	path, err := writePsiphonProfileConfig("agent-bootstrap", 23456, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePsiphonClientConfig(path, "127.0.0.1:23456"); err != nil {
		t.Fatalf("generated bootstrap config did not validate: %v", err)
	}
}

func TestRepairLegacyPsiphonConfigMigratesOnlyPlaceholderBootstrap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy.json")
	legacy := newPsiphonClientConfig(21082)
	legacy.PropagationChannelID = "FFFFFFFFFFFFFFFF"
	legacy.SponsorID = "FFFFFFFFFFFFFFFF"
	legacy.RemoteServerListURLs = nil
	legacy.ObfuscatedServerListRootURLs = nil
	legacy.ServerEntrySignaturePublicKey = ""
	legacy.ExchangeObfuscationKey = ""
	legacy.EgressRegion = "DE"
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyBytes, 0600); err != nil {
		t.Fatal(err)
	}

	migrated, err := repairLegacyPsiphonClientConfig(path, "127.0.0.1:21082")
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("legacy placeholder bootstrap was not migrated")
	}
	if err := validatePsiphonClientConfig(path, "127.0.0.1:21082"); err != nil {
		t.Fatalf("migrated config is not valid: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got psiphonClientConfig
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.EgressRegion != "DE" {
		t.Fatalf("EgressRegion=%q, want DE", got.EgressRegion)
	}
	if got.PropagationChannelID == "FFFFFFFFFFFFFFFF" || got.SponsorID == "FFFFFFFFFFFFFFFF" {
		t.Fatal("placeholder IDs remain after migration")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("migrated config mode=%o, want 600", st.Mode().Perm())
	}
}

func TestRepairLegacyPsiphonConfigMigratesEmptyIdentityAndScalarURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty-legacy.json")
	legacy := newPsiphonClientConfig(21084)
	legacy.PropagationChannelID = ""
	legacy.SponsorID = ""
	legacy.RemoteServerListURLs = nil
	legacy.ObfuscatedServerListRootURLs = nil
	legacy.RemoteServerListSignaturePublicKey = ""
	legacy.ServerEntrySignaturePublicKey = ""
	legacy.ExchangeObfuscationKey = ""
	legacy.RemoteServerListURL = psiphonRemoteServerListURL
	legacy.EgressRegion = "DE"
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyBytes, 0600); err != nil {
		t.Fatal(err)
	}

	migrated, err := repairLegacyPsiphonClientConfig(path, "127.0.0.1:21084")
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("empty legacy Psiphon identity was not migrated")
	}
	if err := validatePsiphonClientConfig(path, "127.0.0.1:21084"); err != nil {
		t.Fatalf("migrated config is not valid: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got psiphonClientConfig
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !isUsablePsiphonClientID(got.PropagationChannelID) || !isUsablePsiphonClientID(got.SponsorID) {
		t.Fatal("empty Psiphon IDs remain after migration")
	}
	if len(got.RemoteServerListURLs) == 0 || len(got.ObfuscatedServerListRootURLs) == 0 {
		t.Fatal("new authenticated server-list URL arrays were not generated")
	}
	if got.EgressRegion != "DE" {
		t.Fatalf("EgressRegion=%q, want DE", got.EgressRegion)
	}
}

func TestRepairLegacyPsiphonConfigPreservesValidIdentityWhenUpdatingScalarBootstrap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-legacy.json")
	legacy := newPsiphonClientConfig(21085)
	legacy.PropagationChannelID = "24BCA4EE20BEB92C"
	legacy.SponsorID = "721AE60D76700F5A"
	legacy.RemoteServerListURLs = nil
	legacy.ObfuscatedServerListRootURLs = nil
	legacy.RemoteServerListURL = psiphonRemoteServerListURL
	legacy.EgressRegion = "NL"
	legacyBytes, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, legacyBytes, 0600); err != nil {
		t.Fatal(err)
	}

	migrated, err := repairLegacyPsiphonClientConfig(path, "127.0.0.1:21085")
	if err != nil {
		t.Fatal(err)
	}
	if !migrated {
		t.Fatal("deprecated scalar bootstrap was not upgraded")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got psiphonClientConfig
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.PropagationChannelID != "24BCA4EE20BEB92C" || got.SponsorID != "721AE60D76700F5A" {
		t.Fatal("valid custom Psiphon identity was not preserved")
	}
	if got.EgressRegion != "NL" {
		t.Fatalf("EgressRegion=%q, want NL", got.EgressRegion)
	}
	if err := validatePsiphonClientConfig(path, "127.0.0.1:21085"); err != nil {
		t.Fatalf("upgraded scalar config is not valid: %v", err)
	}
}

func TestRepairLegacyPsiphonConfigLeavesNonPlaceholderConfigAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.json")
	cfg := newPsiphonClientConfig(21083)
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	migrated, err := repairLegacyPsiphonClientConfig(path, "127.0.0.1:21083")
	if err != nil {
		t.Fatal(err)
	}
	if migrated {
		t.Fatal("valid non-placeholder config should not be rewritten")
	}
}

func TestWritePsiphonProfileConfigIsPrivateAndValid(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "profiles")
	path, err := writePsiphonProfileConfig("agent-primary", 24567, dir)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != tunnelID("agent-primary")+".json" {
		t.Fatalf("unexpected profile config path: %s", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0600 {
		t.Fatalf("config mode = %o, want 600", got)
	}
	st, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0700 {
		t.Fatalf("config directory mode = %o, want 700", got)
	}
	if err := validatePsiphonClientConfig(path, "127.0.0.1:24567"); err != nil {
		t.Fatalf("generated config did not validate: %v", err)
	}
	if err := validatePsiphonClientConfig(path, "0.0.0.0:24567"); err == nil {
		t.Fatal("non-loopback Psiphon proxy must be rejected")
	}
}

func TestAllocatePsiphonSocksPortIsStableAndPrivateRange(t *testing.T) {
	dir := t.TempDir()
	first, err := allocatePsiphonSocksPort("agent-a", dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := allocatePsiphonSocksPort("agent-a", dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("port allocation is not deterministic: %d != %d", first, second)
	}
	if first < 20000 || first > 49999 {
		t.Fatalf("port %d is outside reserved local range", first)
	}
}

func TestParsePsiphonTunnelNotice(t *testing.T) {
	if count, ok := parsePsiphonTunnelNotice(`{"noticeType":"Tunnels","data":{"count":2}}`); !ok || count != 2 {
		t.Fatalf("parsed count=%d ok=%t; want 2,true", count, ok)
	}
	if _, ok := parsePsiphonTunnelNotice(`{"noticeType":"ListeningSocksProxyPort","data":{"port":24567}}`); ok {
		t.Fatal("SOCKS listener notice must not be treated as an established tunnel")
	}
}

func TestValidatePsiphonRejectsUnauthenticatedServerList(t *testing.T) {
	dir := t.TempDir()
	path, err := writePsiphonProfileConfig("agent-invalid", 24568, dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg psiphonClientConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.RemoteServerListSignaturePublicKey = ""
	b, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validatePsiphonClientConfig(path, "127.0.0.1:24568"); err == nil {
		t.Fatal("unauthenticated Psiphon server list must be rejected")
	}
}

func TestPsiphonConsoleClientArgsUseDefaultLoopbackBinding(t *testing.T) {
	args := psiphonConsoleClientArgs("/etc/ravanreverse/psiphon/s.json", "/var/lib/shah-tunnel/psiphon/s")
	want := []string{"-config", "/etc/ravanreverse/psiphon/s.json", "-dataRootDirectory", "/var/lib/shah-tunnel/psiphon/s"}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("Psiphon ConsoleClient args = %#v; want %#v", args, want)
	}
	for _, arg := range args {
		if arg == "-listenInterface" {
			t.Fatal("Psiphon must use its built-in 127.0.0.1 default instead of enumerating interfaces")
		}
	}
}

func TestPsiphonPerformanceProfileIsMemoryAndCPUAware(t *testing.T) {
	low := psiphonPerformanceProfileForHost(1<<30, 1)
	if !low.LimitMeekBufferSizes || !low.LimitRelayBufferSizes || !low.LimitCPUThreads || low.SSHChannelWindowSize != 4 || low.TunnelPoolSize != 2 {
		t.Fatalf("low-resource profile should retain safety limits and the default SSH window: %+v", low)
	}
	highMemorySingleCore := psiphonPerformanceProfileForHost(4<<30, 1)
	if highMemorySingleCore.LimitMeekBufferSizes || highMemorySingleCore.LimitRelayBufferSizes || !highMemorySingleCore.LimitCPUThreads || highMemorySingleCore.SSHChannelWindowSize != 16 || highMemorySingleCore.TunnelPoolSize != 2 {
		t.Fatalf("high-memory single-core profile should expand buffers/window but limit CPU threads: %+v", highMemorySingleCore)
	}
	high := psiphonPerformanceProfileForHost(4<<30, 4)
	if high.LimitMeekBufferSizes || high.LimitRelayBufferSizes || high.LimitCPUThreads || high.SSHChannelWindowSize != 16 || high.TunnelPoolSize != 8 {
		t.Fatalf("high-resource profile should lift conservative throughput limits and use a moderate larger SSH window: %+v", high)
	}
	large := psiphonPerformanceProfileForHost(8<<30, 4)
	if large.TunnelPoolSize != 12 {
		t.Fatalf("8 GiB / 4 CPU profile TunnelPoolSize=%d; want 12", large.TunnelPoolSize)
	}
	max := psiphonPerformanceProfileForHost(16<<30, 8)
	if max.TunnelPoolSize != 16 {
		t.Fatalf("16 GiB / 8 CPU profile TunnelPoolSize=%d; want 16", max.TunnelPoolSize)
	}
}

func TestPsiphonEgressRegionPolicyBlocksUSAndDefaultsToGermany(t *testing.T) {
	if got, err := normalizePsiphonEgressRegion(""); err != nil || got != "DE" {
		t.Fatalf("empty region = %q, %v; want DE", got, err)
	}
	for _, region := range []string{"US", "us", "GB", "XX"} {
		if got, err := normalizePsiphonEgressRegion(region); err == nil {
			t.Fatalf("region %q unexpectedly accepted as %q", region, got)
		}
	}
	for _, region := range []string{"AE", "TR", "DE", "RS", "RO", "FR"} {
		if got, err := normalizePsiphonEgressRegion(region); err != nil || got != region {
			t.Fatalf("approved region %q rejected: got=%q err=%v", region, got, err)
		}
	}
}

func TestTunePsiphonPerformanceConfigPreservesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	original := []byte(`{"EgressRegion":"DE","LocalSocksProxyPort":21086,"UnknownFuturePsiphonOption":{"keep":"me"},"LimitMeekBufferSizes":true,"LimitCPUThreads":true,"LimitRelayBufferSizes":true,"SSHChannelWindowSize":4,"TunnelPoolSize":1}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := tunePsiphonPerformanceConfigForProfile(path, psiphonPerformanceProfileForHost(4<<30, 4))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected performance settings to be reconciled")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["EgressRegion"]) != `"DE"` || string(got["LocalSocksProxyPort"]) != "21086" {
		t.Fatalf("known profile fields were not preserved: region=%s port=%s", got["EgressRegion"], got["LocalSocksProxyPort"])
	}
	if string(got["SSHChannelWindowSize"]) != "16" {
		t.Fatalf("SSHChannelWindowSize=%s; want 16 for high-memory host", got["SSHChannelWindowSize"])
	}
	if string(got["TunnelPoolSize"]) != "8" {
		t.Fatalf("TunnelPoolSize=%s; want 8 for 4 GiB / 4 CPU host", got["TunnelPoolSize"])
	}
	var unknown map[string]string
	if err := json.Unmarshal(got["UnknownFuturePsiphonOption"], &unknown); err != nil || unknown["keep"] != "me" {
		t.Fatalf("unknown Psiphon option was not preserved: value=%s err=%v", got["UnknownFuturePsiphonOption"], err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("tuned config mode=%o, want 600", st.Mode().Perm())
	}
	changed, err = tunePsiphonPerformanceConfigForProfile(path, psiphonPerformanceProfileForHost(4<<30, 4))
	if err != nil || changed {
		t.Fatalf("second tune should be a no-op: changed=%t err=%v", changed, err)
	}
}

func TestPsiphonEgressRegionPriorityAndUSBlock(t *testing.T) {
	want := []string{"DE", "TR", "AE", "RS", "RO", "BG", "GR", "GE", "AM", "AZ", "NL", "CH", "AT", "PL", "CZ", "SK", "HU", "FR", "SE", "FI"}
	if !reflect.DeepEqual(psiphonEgressRegionPriority, want) {
		t.Fatalf("Psiphon region priority = %v; want %v", psiphonEgressRegionPriority, want)
	}
	for _, region := range want {
		if _, err := normalizePsiphonEgressRegion(region); err != nil {
			t.Fatalf("priority region %s was rejected: %v", region, err)
		}
	}
	for _, blocked := range []string{"US", "us", "USA"} {
		if _, err := normalizePsiphonEgressRegion(blocked); err == nil {
			t.Fatalf("blocked region %q was accepted", blocked)
		}
	}
}

func TestRenderPsiphonSystemdServiceStaysWarmAcrossAgentRestarts(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Name:           "profile-s",
		PsiphonConfig:  filepath.Join(dir, "psiphon.json"),
		PsiphonClient:  "/usr/local/bin/psiphon-console-client",
		PsiphonDataDir: filepath.Join(dir, "data"),
	}
	service := psiphonServiceName(cfg.Name)
	unit, err := renderPsiphonServiceUnit(cfg, service, "ravanreverse@s")
	if err != nil {
		t.Fatal(err)
	}
	text := string(unit)
	for _, want := range []string{
		"Restart=always",
		"RestartSec=2",
		`ExecStart="/usr/local/bin/psiphon-console-client" "-config"`,
		"-dataRootDirectory",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Psiphon unit missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "PartOf=ravanreverse@s.service") {
		t.Fatalf("Psiphon must not be coupled to Agent restart jobs; its tunnels should remain warm:\n%s", text)
	}
	if strings.Contains(text, "[Install]") || strings.Contains(text, "WantedBy=multi-user.target") {
		t.Fatalf("per-profile Psiphon service must be started through its Agent dependency, not enabled globally:\n%s", text)
	}
	if strings.Contains(text, "0.0.0.0") || strings.Contains(text, "CAP_NET_ADMIN") {
		t.Fatalf("Psiphon unit must not expose a public proxy or grant network-admin capability:\n%s", text)
	}
}
