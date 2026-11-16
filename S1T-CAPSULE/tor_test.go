package main

import (
	"strings"
	"testing"
)

const testWebTunnelBridge = "Bridge webtunnel 203.0.113.5:443 0123456789abcdef0123456789abcdef01234567 url=https://bridge.example.net/ ver=0.0.1"

func TestValidateTorWebTunnelBridgeLine(t *testing.T) {
	if err := validateTorBridgeLine(testWebTunnelBridge); err != nil {
		t.Fatalf("valid WebTunnel bridge was rejected: %v", err)
	}
	invalid := []string{
		"",
		"Bridge obfs4 203.0.113.5:443 0123456789abcdef0123456789abcdef01234567 cert=x iat-mode=0",
		"Bridge webtunnel 203.0.113.5:443 not-a-fingerprint url=https://bridge.example.net/ ver=0.0.1",
		"Bridge webtunnel 203.0.113.5:443 0123456789abcdef0123456789abcdef01234567 url=http://bridge.example.net/ ver=0.0.1",
		"Bridge webtunnel 203.0.113.5:443 0123456789abcdef0123456789abcdef01234567 url=https://bridge.example.net/",
		testWebTunnelBridge + "\nSocksPort 0",
		testWebTunnelBridge + " # injected",
	}
	for _, input := range invalid {
		if err := validateTorBridgeLine(input); err == nil {
			t.Errorf("invalid WebTunnel bridge was accepted: %q", input)
		}
	}
}

func TestTorBridgeLineSelectsSnowflakeOrWebTunnel(t *testing.T) {
	line, err := torBridgeLine(Config{TorMode: torModeSnowflake})
	if err != nil {
		t.Fatalf("default Snowflake bridge failed validation: %v", err)
	}
	if !strings.HasPrefix(line, "Bridge snowflake ") || !strings.Contains(line, "utls-imitate=") {
		t.Fatalf("unexpected Snowflake bridge line: %s", line)
	}
	line, err = torBridgeLine(Config{TorMode: torModeWebTunnel, TorBridge: testWebTunnelBridge})
	if err != nil || line != testWebTunnelBridge {
		t.Fatalf("WebTunnel bridge selection = %q, err=%v", line, err)
	}
	if _, err := torBridgeLine(Config{TorMode: "unknown"}); err == nil {
		t.Fatal("unknown Tor bridge mode was accepted")
	}
}

func TestBuildTorClientConfigIsLoopbackOnlyAndProfileScoped(t *testing.T) {
	cfg := Config{
		TorMode:       torModeSnowflake,
		TorProxy:      "127.0.0.1:19050",
		TorDataDir:    torDataRoot + "/agent-s",
		TorConfigPath: torConfigDir + "/agent-s.torrc",
		TorBinary:     torBundleRoot + "/tor/tor",
		TorPTBinary:   torBundleRoot + "/tor/pluggable_transports/lyrebird",
	}
	got, err := buildTorClientConfig(cfg)
	if err != nil {
		t.Fatalf("buildTorClientConfig failed: %v", err)
	}
	for _, want := range []string{
		"RunAsDaemon 0\n",
		"ClientOnly 1\n",
		"UseBridges 1\n",
		"DataDirectory " + cfg.TorDataDir + "\n",
		"SocksPort 127.0.0.1:19050 IsolateSOCKSAuth\n",
		"ClientTransportPlugin snowflake,webtunnel exec " + cfg.TorPTBinary + "\n",
		"Bridge snowflake ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Tor config missing %q", want)
		}
	}
	if strings.Contains(got, "SocksPort 0.0.0.0") || strings.Contains(got, "SocksPort 0\n") {
		t.Fatal("Tor SOCKS endpoint must never listen on a public interface")
	}
}

func TestBuildTorClientConfigRejectsUnsafePathsAndPublicProxy(t *testing.T) {
	base := Config{
		TorMode:       torModeSnowflake,
		TorProxy:      "127.0.0.1:19050",
		TorDataDir:    torDataRoot + "/agent-s",
		TorConfigPath: torConfigDir + "/agent-s.torrc",
		TorBinary:     torBundleRoot + "/tor/tor",
		TorPTBinary:   torBundleRoot + "/tor/pluggable_transports/lyrebird",
	}
	unsafe := base
	unsafe.TorDataDir = torDataRoot + "/../outside"
	if _, err := buildTorClientConfig(unsafe); err == nil {
		t.Fatal("Tor data directory traversal was accepted")
	}
	unsafe = base
	unsafe.TorConfigPath = torConfigDir + "/../outside.torrc"
	if _, err := buildTorClientConfig(unsafe); err == nil {
		t.Fatal("Tor config path traversal was accepted")
	}
	unsafe = base
	unsafe.TorProxy = "0.0.0.0:19050"
	if _, err := buildTorClientConfig(unsafe); err == nil {
		t.Fatal("public Tor SOCKS listener was accepted")
	}
	unsafe = base
	unsafe.TorPTBinary = "/tmp/path with spaces/lyrebird"
	if _, err := buildTorClientConfig(unsafe); err == nil {
		t.Fatal("binary path containing whitespace was accepted")
	}
}

func TestTorRuntimeEnvironmentAddsOnlyBundleLibraryPaths(t *testing.T) {
	t.Setenv("LD_LIBRARY_PATH", "/custom/lib")
	cfg := Config{
		TorBinary:   torBundleRoot + "/tor/tor",
		TorPTBinary: torBundleRoot + "/tor/pluggable_transports/lyrebird",
	}
	env := strings.Join(torRuntimeEnvironment(cfg), "\n")
	if !strings.Contains(env, "LD_LIBRARY_PATH="+torBundleRoot+"/tor:"+torBundleRoot+"/tor/pluggable_transports:/custom/lib") {
		t.Fatalf("bundle library paths were not prepended correctly: %s", env)
	}
	cfg.TorBinary = "/usr/bin/tor"
	cfg.TorPTBinary = "/usr/bin/lyrebird"
	env = strings.Join(torRuntimeEnvironment(cfg), "\n")
	if strings.Contains(env, "LD_LIBRARY_PATH=/usr/bin") {
		t.Fatalf("system-installed binaries should not modify library lookup paths: %s", env)
	}
}
