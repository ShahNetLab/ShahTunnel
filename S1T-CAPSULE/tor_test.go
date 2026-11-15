package main

import (
	"context"
	"strings"
	"testing"
	"time"
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

func TestTorAgentReadinessRequiresBootstrapAndAuthenticatedLane(t *testing.T) {
	installOnly := `Tor and Lyrebird are installed; the private per-profile SOCKS5 endpoint is configured`
	boot, lane := torAgentReadinessFromJournal(installOnly)
	if boot || lane {
		t.Fatalf("installation messages must not be treated as runtime readiness: bootstrap=%t lane=%t", boot, lane)
	}

	bootstrapOnly := `[notice] Bootstrapped 100% (done): Done
Tor transport bootstrapped successfully; SOCKS5 proxy is 127.0.0.1:19082`
	boot, lane = torAgentReadinessFromJournal(bootstrapOnly)
	if !boot || lane {
		t.Fatalf("bootstrap-only journal parsed incorrectly: bootstrap=%t lane=%t", boot, lane)
	}

	ready := bootstrapOnly + `
tunnel lane 1/12 connected via tcp_tls over tor_socks5; forwarding through 1 configured port mapping(s)`
	boot, lane = torAgentReadinessFromJournal(ready)
	if !boot || !lane {
		t.Fatalf("fully ready Tor journal parsed incorrectly: bootstrap=%t lane=%t", boot, lane)
	}

	wrongUnderlay := bootstrapOnly + `
tunnel lane 1/12 connected via tcp_tls over direct`
	boot, lane = torAgentReadinessFromJournal(wrongUnderlay)
	if !boot || lane {
		t.Fatalf("direct lane must not satisfy Tor readiness: bootstrap=%t lane=%t", boot, lane)
	}
}

func TestWaitForTorBootstrapHasNoArbitraryDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	processDone := make(chan error, 1)
	bootstrap := make(chan struct{}, 1)
	result := make(chan bool, 1)
	go func() {
		ready, _ := waitForTorBootstrap(ctx, processDone, bootstrap)
		result <- ready
	}()

	select {
	case ready := <-result:
		t.Fatalf("Tor bootstrap returned before the bridge reported readiness: %t", ready)
	case <-time.After(80 * time.Millisecond):
		// Expected: a still-running Tor process is allowed to keep bootstrapping.
	}

	bootstrap <- struct{}{}
	select {
	case ready := <-result:
		if !ready {
			t.Fatal("Tor bootstrap event was not recognized")
		}
	case <-time.After(time.Second):
		t.Fatal("Tor bootstrap waiter did not return after readiness")
	}
}

func TestWaitForTorBootstrapReturnsWhenProcessExits(t *testing.T) {
	ctx := context.Background()
	processDone := make(chan error, 1)
	bootstrap := make(chan struct{})
	processDone <- nil
	ready, err := waitForTorBootstrap(ctx, processDone, bootstrap)
	if ready || err == nil || !strings.Contains(err.Error(), "Tor exited before bootstrap") {
		t.Fatalf("unexpected result for early Tor exit: ready=%t err=%v", ready, err)
	}
}
