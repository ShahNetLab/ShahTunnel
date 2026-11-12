package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNewPsiphonClientConfigUsesAuthenticatedBootstrap(t *testing.T) {
	cfg := newPsiphonClientConfig(23456)
	if cfg.LocalSocksProxyPort != 23456 {
		t.Fatalf("SOCKS port = %d, want 23456", cfg.LocalSocksProxyPort)
	}
	if cfg.PropagationChannelID == "" || cfg.SponsorID == "" || cfg.ClientVersion == "" {
		t.Fatal("Psiphon client identity fields must be populated")
	}
	if cfg.RemoteServerListURL == "" || cfg.RemoteServerListSignaturePublicKey == "" {
		t.Fatal("authenticated public server-list bootstrap is incomplete")
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
