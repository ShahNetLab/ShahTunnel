package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
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
