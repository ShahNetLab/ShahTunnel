package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildPsiphonDoHProbeQueryAndResponseValidation(t *testing.T) {
	query, err := buildPsiphonDoHProbeQuery("example.com", 0x5a31)
	if err != nil {
		t.Fatal(err)
	}
	if len(query) < 12 || query[0] != 0x5a || query[1] != 0x31 || query[5] != 1 {
		t.Fatalf("unexpected DNS query header: %x", query[:12])
	}
	// A minimal valid response echoes the transaction ID and sets QR with RCODE=0.
	response := append([]byte(nil), query[:12]...)
	response[2] = 0x81
	response[3] = 0x80
	if !validPsiphonDoHResponse(response, 0x5a31) {
		t.Fatal("valid DoH DNS response was rejected")
	}
	response[1]++
	if validPsiphonDoHResponse(response, 0x5a31) {
		t.Fatal("DoH response with a different transaction ID was accepted")
	}
	if _, err := buildPsiphonDoHProbeQuery("bad..example", 1); err == nil {
		t.Fatal("malformed DNS labels must be rejected")
	}
}

func TestPsiphonHubProbeAuthenticatesThroughTheConfiguredMappingEndpoint(t *testing.T) {
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "hub.crt"), filepath.Join(certDir, "hub.key")
	fingerprint, err := generateCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("generate Hub certificate: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load Hub certificate: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	h := &hubServer{
		cfg:              Config{Role: "hub", Transport: transportAdaptive, Token: strings.Repeat("ab", 32)},
		controlTLSConfig: hubTLSConfig(cert),
		sessions:         make(map[*hubSession]struct{}),
		pendingPublic:    make(chan struct{}, maxPendingPublicConnections),
	}
	go h.acceptPublic(listener, "main")
	proxyAddress := startTestSOCKS5Relay(t, listener.Addr().String())

	cfg := Config{
		Role:           "agent",
		Transport:      transportAdaptive,
		Underlay:       underlayPsiphon,
		HubAddr:        "127.0.0.1:9443",
		PsiphonHubAddr: listener.Addr().String(),
		PsiphonProxy:   proxyAddress,
		TLSServerName:  "localhost",
		Token:          h.cfg.Token,
		Fingerprint:    fingerprint,
		Ports:          []PortMapping{{ID: "main", Target: "127.0.0.1:2083"}},
	}
	if err := verifyPsiphonHubControlPath(cfg, proxyAddress, 8*time.Second); err != nil {
		t.Fatalf("authenticated Hub probe through Psiphon failed: %v", err)
	}
	if got := psiphonHubProbeEndpoint(cfg); got != listener.Addr().String() {
		t.Fatalf("probe endpoint = %q; want explicit Mapping endpoint %q", got, listener.Addr().String())
	}
	if got := cfg.Ports[0].Target; got != "127.0.0.1:2083" {
		t.Fatalf("customer Xray target was changed by the Hub probe: %q", got)
	}
}

func TestPsiphonHubProbeReportsSOCKSRefusalForTheActualTransitPort(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	transitEndpoint := target.Addr().String()
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	proxyAddress := startTestSOCKS5Relay(t, transitEndpoint)
	cfg := Config{
		Role:           "agent",
		Transport:      transportTCP,
		Underlay:       underlayPsiphon,
		HubAddr:        "127.0.0.1:9443",
		PsiphonHubAddr: transitEndpoint,
		PsiphonProxy:   proxyAddress,
		Token:          strings.Repeat("cd", 32),
		Fingerprint:    strings.Repeat("a", 64),
		Ports:          []PortMapping{{ID: "main", Target: "127.0.0.1:2083"}},
	}
	err = verifyPsiphonHubControlPath(cfg, proxyAddress, 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "SOCKS5 CONNECT rejected (reply=5)") {
		t.Fatalf("expected the actual transit-port SOCKS5 refusal to be reported, got %v", err)
	}
	if !strings.Contains(err.Error(), transitEndpoint) {
		t.Fatalf("probe error does not identify the configured transit endpoint %q: %v", transitEndpoint, err)
	}
	if got := cfg.Ports[0].Target; got != "127.0.0.1:2083" {
		t.Fatalf("customer Xray target was changed after a rejected Hub probe: %q", got)
	}
}

func TestXrayPsiphonUnitOwnershipAllowsOnlyExactProfileService(t *testing.T) {
	runtime := xrayRuntime{Binary: "/usr/local/bin/xray", CWD: "/usr/local/bin"}
	service := "shah-tunnel-xray-psiphon-s.service"
	configPath := "/etc/ravanreverse/xray-psiphon/s/config.json"
	unit, err := renderXrayPsiphonUnit(runtime, configPath, service)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "Managed-By: ShahTunnel 5.5.10") {
		t.Fatal("rendered sidecar unit is missing the ShahTunnel ownership marker")
	}
	if !xrayPsiphonUnitBelongsToProfile(unit, runtime, configPath, service) {
		t.Fatal("newly rendered ShahTunnel sidecar unit was not recognized as owned")
	}
	// A Go/Xray upgrade may change the executable path. The old service remains
	// ours when its exact profile config path and ShahTunnel description match.
	oldBinary := strings.ReplaceAll(string(unit), `"/usr/local/bin/xray" run -config`, `"/opt/xray/bin/xray" run -config`)
	if !xrayPsiphonUnitBelongsToProfile([]byte(oldBinary), runtime, configPath, service) {
		t.Fatal("managed unit from an older Xray binary path was not recognized for repair")
	}
	if xrayPsiphonUnitBelongsToProfile(unit, runtime, "/etc/ravanreverse/xray-psiphon/other/config.json", service) {
		t.Fatal("sidecar unit was accepted for a different profile config path")
	}
	if xrayPsiphonUnitBelongsToProfile(unit, runtime, configPath, "unrelated.service") {
		t.Fatal("unrelated systemd service name was accepted")
	}
	foreign := []byte("[Unit]\nDescription=Third-party service\n\n[Service]\nExecStart=/usr/bin/xray run -config \"" + configPath + "\"\n")
	if xrayPsiphonUnitBelongsToProfile(foreign, runtime, configPath, service) {
		t.Fatal("third-party systemd unit was accepted for replacement")
	}
}

func TestXrayPsiphonLifecycleOwnershipRequiresExactProfileMetadata(t *testing.T) {
	runtime := xrayRuntime{Binary: "/usr/local/bin/xray", CWD: "/usr/local/bin"}
	cfg := Config{
		Name:         "profile-s",
		PsiphonProxy: "127.0.0.1:21083",
		XrayPsiphon: &XrayPsiphonIntegration{
			ConfigPath: "/etc/ravanreverse/xray-psiphon/profile-s/config.json",
			Service:    "shah-tunnel-xray-psiphon-profile-s.service",
			Proxy:      "127.0.0.1:21083",
			Bindings:   []XrayPsiphonBinding{{MappingID: "main", OriginalTarget: "127.0.0.1:2083", PsiphonTarget: "127.0.0.1:31083"}},
		},
	}
	unit, err := renderXrayPsiphonUnit(runtime, cfg.XrayPsiphon.ConfigPath, cfg.XrayPsiphon.Service)
	if err != nil {
		t.Fatal(err)
	}
	if !xrayPsiphonUnitBelongsToConfig(unit, cfg) {
		t.Fatal("profile's own Xray Psiphon unit was not recognized for lifecycle management")
	}
	other := cfg
	other.Name = "another-profile"
	if xrayPsiphonUnitBelongsToConfig(unit, other) {
		t.Fatal("Xray Psiphon unit was accepted for a different profile")
	}
	other = cfg
	other.PsiphonProxy = "127.0.0.1:21084"
	if xrayPsiphonUnitBelongsToConfig(unit, other) {
		t.Fatal("Xray Psiphon unit was accepted with a different SOCKS endpoint")
	}
	other = cfg
	other.XrayPsiphon = &XrayPsiphonIntegration{ConfigPath: "/etc/ravanreverse/xray-psiphon/other/config.json", Service: cfg.XrayPsiphon.Service, Proxy: cfg.PsiphonProxy, Bindings: cfg.XrayPsiphon.Bindings}
	if xrayPsiphonUnitBelongsToConfig(unit, other) {
		t.Fatal("Xray Psiphon unit was accepted for a different managed config")
	}
}

func TestPsiphonMappingsMustPointToIsolatedSidecar(t *testing.T) {
	cfg := Config{
		Ports: []PortMapping{{ID: "main", Target: "127.0.0.1:31083"}},
		XrayPsiphon: &XrayPsiphonIntegration{
			Bindings: []XrayPsiphonBinding{{MappingID: "main", OriginalTarget: "127.0.0.1:2083", PsiphonTarget: "127.0.0.1:31083"}},
		},
	}
	if err := validatePsiphonMappingTargets(cfg); err != nil {
		t.Fatalf("valid isolated mapping rejected: %v", err)
	}
	cfg.Ports[0].Target = "127.0.0.1:2083"
	if err := validatePsiphonMappingTargets(cfg); err == nil {
		t.Fatal("original Xray target must be rejected as possible direct egress")
	}
}

func TestNextPsiphonRotationCandidatesAdvanceAndWrap(t *testing.T) {
	want := []string{"BR", "CH", "CZ", "DE", "ES", "GB", "IE", "IT", "LT", "NL", "NO", "PL", "RO"}
	got := nextPsiphonRotationCandidates("AT")
	if len(got) != len(want) {
		t.Fatalf("rotation candidate count=%d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rotation candidate %d=%s, want %s", i, got[i], want[i])
		}
	}
	if got := nextPsiphonRotationCandidates("RO"); got[0] != "AT" {
		t.Fatalf("rotation should wrap from RO to AT, got first=%s", got[0])
	}
	for _, region := range got {
		if region == "AT" {
			t.Fatal("rotation list must not retry the currently active country")
		}
	}
}

func TestRenderPsiphonRotationUnitsAreProfileScopedAndHourly(t *testing.T) {
	service, timer, err := renderPsiphonRotationUnits("s", "/usr/local/bin/ravanreverse", "/etc/ravanreverse/tunnels/s.json")
	if err != nil {
		t.Fatal(err)
	}
	serviceText, timerText := string(service), string(timer)
	for _, want := range []string{
		"Description=ShahTunnel hourly Psiphon country rotation (s)",
		`"/usr/local/bin/ravanreverse" rotate-psiphon-country --config "/etc/ravanreverse/tunnels/s.json"`,
		"ProtectSystem=full",
		"ReadWritePaths=/etc/ravanreverse/psiphon /run/lock",
	} {
		if !strings.Contains(serviceText, want) {
			t.Fatalf("rotation service missing %q:\n%s", want, serviceText)
		}
	}
	for _, want := range []string{"OnBootSec=1h", "OnUnitActiveSec=1h", "AccuracySec=1min", "Unit=shah-tunnel-psiphon-rotate-s.service"} {
		if !strings.Contains(timerText, want) {
			t.Fatalf("rotation timer missing %q:\n%s", want, timerText)
		}
	}
	if _, _, err := renderPsiphonRotationUnits("s", "relative/binary", "/etc/ravanreverse/tunnels/s.json"); err == nil {
		t.Fatal("relative executable path must be rejected")
	}
}

func TestMigrateXrayPsiphonHomeProtection(t *testing.T) {
	oldUnit := []byte(`[Unit]
Description=ShahTunnel isolated Psiphon Xray (s)
After=network-online.target

[Service]
Type=simple
ProtectHome=yes
ProtectSystem=full
ExecStart="/usr/local/x-ui/bin/xray-linux-amd64" run -config "/etc/ravanreverse/xray-psiphon/s/config.json"

[Install]
WantedBy=multi-user.target
`)
	updated, changed, err := migrateXrayPsiphonHomeProtection(oldUnit)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !strings.Contains(string(updated), "ProtectHome=read-only") || strings.Contains(string(updated), "ProtectHome=yes") {
		t.Fatalf("old sidecar unit was not migrated to read-only home access: changed=%t\n%s", changed, updated)
	}
	updatedAgain, changedAgain, err := migrateXrayPsiphonHomeProtection(updated)
	if err != nil {
		t.Fatal(err)
	}
	if changedAgain || string(updatedAgain) != string(updated) {
		t.Fatalf("home-protection migration is not idempotent: changed=%t", changedAgain)
	}
	if _, _, err := migrateXrayPsiphonHomeProtection([]byte("[Unit]\nDescription=Third-party\n[Service]\nProtectHome=yes\n")); err == nil {
		t.Fatal("migration must reject a non-ShahTunnel unit")
	}
	duplicate := strings.Replace(string(oldUnit), "ProtectHome=yes\n", "ProtectHome=yes\nProtectHome=no\n", 1)
	if _, _, err := migrateXrayPsiphonHomeProtection([]byte(duplicate)); err == nil {
		t.Fatal("migration must reject duplicate ProtectHome directives")
	}
}

func TestMigrateXrayPsiphonDNSConfig(t *testing.T) {
	input := []byte(`{
  "inbounds": [{"tag":"s1t-psiphon-profile-s-main","listen":"127.0.0.1","port":35627,"protocol":"vless"}],
  "outbounds": [
    {"tag":"s1t-psiphon-profile-s-out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":21082}]}},
    {"tag":"s1t-psiphon-profile-s-dns-out","protocol":"dns","settings":{}}
  ],
  "dns": {"tag":"dns_inbound","servers":["https://cloudflare-dns.com/dns-query"]},
  "routing": {"rules":[
    {"type":"field","inboundTag":["s1t-psiphon-profile-s-main"],"network":"tcp,udp","port":"53","outboundTag":"s1t-psiphon-profile-s-dns-out","ruleTag":"s1t-psiphon-profile-s-dns-hijack"},
    {"type":"field","inboundTag":["dns_inbound"],"outboundTag":"s1t-psiphon-profile-s-out","ruleTag":"s1t-psiphon-profile-s-dns-egress"},
    {"type":"field","domain":["geosite:category-ads-all"],"outboundTag":"block"}
  ]}
}`)
	bindings := []XrayPsiphonBinding{{MappingID: "main", OriginalTarget: "127.0.0.1:2083", PsiphonTarget: "127.0.0.1:35627", InboundTag: "s1t-psiphon-profile-s-main"}}
	got, changed, err := migrateXrayPsiphonDNSConfig(input, "profile-s", "s1t-psiphon-profile-s-out", bindings)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("legacy DNS routing should have been migrated")
	}
	var config map[string]any
	if err := json.Unmarshal(got, &config); err != nil {
		t.Fatal(err)
	}
	dns := config["dns"].(map[string]any)
	if dns["tag"] != "s1t-psiphon-profile-s-dns-in" {
		t.Fatalf("DNS tag=%v", dns["tag"])
	}
	if dns["enableParallelQuery"] != false {
		t.Fatalf("parallel DNS should be disabled: %v", dns["enableParallelQuery"])
	}
	servers := dns["servers"].([]any)
	if len(servers) != 2 || servers[0] != "https://cloudflare-dns.com/dns-query" || servers[1] != "https://dns.google/dns-query" {
		t.Fatalf("unexpected DoH servers: %#v", servers)
	}
	rules := config["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("routing rules count=%d, want preserved 3: %#v", len(rules), rules)
	}
	first := rules[0].(map[string]any)
	if first["ruleTag"] != "s1t-psiphon-profile-s-dns-hijack" {
		t.Fatalf("first DNS hijack rule not migrated: %#v", first)
	}
	second := rules[1].(map[string]any)
	if second["inboundTag"].([]any)[0] != "s1t-psiphon-profile-s-dns-in" || second["outboundTag"] != "s1t-psiphon-profile-s-out" {
		t.Fatalf("DNS egress not routed through Psiphon: %#v", second)
	}
	third := rules[2].(map[string]any)
	if third["outboundTag"] != "block" {
		t.Fatalf("unrelated routing rule was not preserved: %#v", third)
	}
	again, changedAgain, err := migrateXrayPsiphonDNSConfig(got, "profile-s", "s1t-psiphon-profile-s-out", bindings)
	if err != nil {
		t.Fatal(err)
	}
	if changedAgain || string(again) != string(got) {
		t.Fatal("DNS migration must be idempotent")
	}
}

func TestParseSystemdQuotedArgumentForPsiphonUnit(t *testing.T) {
	binary := `/usr/local/x-ui/bin/xray-linux-amd64`
	config := `/etc/ravanreverse/xray-psiphon/s/config.json`
	first, rest, err := parseSystemdQuotedArgument(systemdExecQuote(binary) + " run -config " + systemdExecQuote(config))
	if err != nil {
		t.Fatal(err)
	}
	if first != binary || rest != "run -config "+systemdExecQuote(config) {
		t.Fatalf("parsed ExecStart mismatch: %q | %q", first, rest)
	}
}
