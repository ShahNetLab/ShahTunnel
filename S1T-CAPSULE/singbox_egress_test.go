package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testProtocolEgressTUIC() ProtocolEgress {
	return ProtocolEgress{
		Protocol: egressTUIC, Server: "exit.example.net", ServerPort: 443,
		UUID: "059032a9-7d40-4a96-9bb1-36823d848068", Password: "test-password",
		ServerName: "exit.example.net", CongestionControl: "bbr", Proxy: "127.0.0.1:32145",
	}
}

func testProtocolEgressReality() ProtocolEgress {
	return ProtocolEgress{
		Protocol: egressReality, Server: "exit.example.net", ServerPort: 443,
		UUID: "059032a9-7d40-4a96-9bb1-36823d848068", ServerName: "cover.example.net",
		PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ShortID: "0123456789abcdef",
		Fingerprint: "chrome", Proxy: "127.0.0.1:32146",
	}
}

func TestRenderSingBoxUnitAllowsNetlinkForInterfaceDetection(t *testing.T) {
	unit, err := renderSingBoxUnit(
		"/usr/local/bin/sing-box",
		"/etc/ravanreverse/sing-box/tuic/profile-s/config.json",
		"shah-tunnel-singbox-tuic-profile-s.service",
	)
	if err != nil {
		t.Fatalf("render sing-box service unit: %v", err)
	}
	text := string(unit)
	if !strings.Contains(text, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK") {
		t.Fatalf("sing-box unit must allow AF_NETLINK for route.auto_detect_interface; generated unit:\n%s", text)
	}
	if strings.Contains(text, "CAP_NET_ADMIN") || strings.Contains(text, "CapabilityBoundingSet=CAP_NET_ADMIN") {
		t.Fatalf("sing-box must not receive CAP_NET_ADMIN just to read interface metadata:\n%s", text)
	}
}

func TestBuildSingBoxEgressConfigTUIC(t *testing.T) {
	p := testProtocolEgressTUIC()
	cfg, err := buildSingBoxEgressConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(cfg, &root); err != nil {
		t.Fatal(err)
	}
	inbounds := root["inbounds"].([]any)
	in := inbounds[0].(map[string]any)
	if in["type"] != "socks" || in["listen"] != "127.0.0.1" || in["listen_port"] != float64(32145) {
		t.Fatalf("unexpected loopback SOCKS inbound: %#v", in)
	}
	out := root["outbounds"].([]any)[0].(map[string]any)
	if out["type"] != "tuic" || out["uuid"] != p.UUID || out["password"] != p.Password || out["zero_rtt_handshake"] != false || out["udp_relay_mode"] != "native" {
		t.Fatalf("unexpected TUIC outbound: %#v", out)
	}
	tls := out["tls"].(map[string]any)
	if tls["server_name"] != p.ServerName || tls["insecure"] != false {
		t.Fatalf("invalid TLS verification config: %#v", tls)
	}
	route := root["route"].(map[string]any)
	if route["final"] != "s1t-egress" {
		t.Fatal("sing-box final route does not select protocol egress")
	}
	if route["auto_detect_interface"] != true {
		t.Fatal("sing-box must retain automatic interface detection for the selected egress")
	}
}

func TestBuildSingBoxEgressConfigVLESSReality(t *testing.T) {
	p := testProtocolEgressReality()
	cfg, err := buildSingBoxEgressConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(cfg, &root); err != nil {
		t.Fatal(err)
	}
	out := root["outbounds"].([]any)[0].(map[string]any)
	if out["type"] != "vless" || out["uuid"] != p.UUID || out["flow"] != "xtls-rprx-vision" || out["packet_encoding"] != "xudp" {
		t.Fatalf("unexpected VLESS outbound: %#v", out)
	}
	tls := out["tls"].(map[string]any)
	if tls["server_name"] != p.ServerName {
		t.Fatalf("unexpected REALITY server_name: %#v", tls)
	}
	if tls["utls"].(map[string]any)["fingerprint"] != "chrome" {
		t.Fatal("uTLS fingerprint was not set")
	}
	reality := tls["reality"].(map[string]any)
	if reality["enabled"] != true || reality["public_key"] != p.PublicKey || reality["short_id"] != p.ShortID {
		t.Fatalf("unexpected REALITY client config: %#v", reality)
	}
}

func TestValidProtocolEgressRejectsMismatchedAndUnsafeSettings(t *testing.T) {
	p := testProtocolEgressTUIC()
	cfg := Config{Role: "agent", Underlay: underlayTUIC, ProtocolEgress: &p}
	if err := validProtocolEgress(cfg); err != nil {
		t.Fatalf("valid TUIC config rejected: %v", err)
	}
	cfg.ProtocolEgress.Protocol = egressReality
	if err := validProtocolEgress(cfg); err == nil {
		t.Fatal("mismatched TUIC/REALITY selection accepted")
	}
	cfg.Underlay = underlayReality
	cfg.ProtocolEgress = &ProtocolEgress{Protocol: egressReality, Server: "exit.example.net", ServerPort: 443, UUID: "059032a9-7d40-4a96-9bb1-36823d848068", ServerName: "cover.example.net", PublicKey: "not-a-public-key", ShortID: "0123456789abcdef"}
	if err := validProtocolEgress(cfg); err == nil {
		t.Fatal("invalid REALITY public key accepted")
	}
	cfg.ProtocolEgress = &ProtocolEgress{Protocol: egressTUIC, Server: "exit.example.net", ServerPort: 443, UUID: "059032a9-7d40-4a96-9bb1-36823d848068", ServerName: "exit.example.net", Password: "pw", Proxy: "0.0.0.0:1080"}
	if err := validProtocolEgress(cfg); err == nil {
		t.Fatal("non-loopback SOCKS proxy accepted")
	}
}

func TestBuildXrayEgressConfigSupportsProtocolSidecarsWithoutUDPBlackhole(t *testing.T) {
	original := []byte(`{"inbounds":[{"tag":"user-in","listen":"127.0.0.1","port":443,"protocol":"vless","settings":{"clients":[]}}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	for _, kind := range []string{egressTUIC, egressReality} {
		generated, bindings, _, err := buildXrayEgressConfig(original, "test-profile", "127.0.0.1:32147", []PortMapping{{ID: "main", Target: "127.0.0.1:443"}}, kind, false)
		if err != nil {
			t.Fatalf("build %s Xray config: %v", kind, err)
		}
		if len(bindings) != 1 || !isLoopbackProxyAddress(bindings[0].WarpTarget) {
			t.Fatalf("invalid %s sidecar binding: %#v", kind, bindings)
		}
		var root map[string]any
		if err := json.Unmarshal(generated, &root); err != nil {
			t.Fatal(err)
		}
		outbounds := root["outbounds"].([]any)
		foundProxy := false
		for _, raw := range outbounds {
			out := raw.(map[string]any)
			if out["tag"] == "s1t-"+kind+"-test-profile-out" {
				foundProxy = true
			}
			if out["protocol"] == "blackhole" {
				t.Fatalf("%s unexpectedly blackholes UDP", kind)
			}
		}
		if !foundProxy {
			t.Fatalf("%s route SOCKS outbound missing", kind)
		}
		rules := root["routing"].(map[string]any)["rules"].([]any)
		if len(rules) == 0 {
			t.Fatalf("%s route has no Xray routing rules", kind)
		}
		encoded, _ := json.Marshal(root)
		if strings.Contains(string(encoded), "0.0.0.0:32147") {
			t.Fatalf("%s sidecar escaped loopback", kind)
		}
	}
}

func TestValidateDistinctExitIP(t *testing.T) {
	if err := validateDistinctExitIP("203.0.113.10", "198.51.100.20"); err != nil {
		t.Fatalf("different valid exit IPs rejected: %v", err)
	}
	if err := validateDistinctExitIP("198.51.100.20", "198.51.100.20"); err == nil {
		t.Fatal("identical direct and protocol exit IPs accepted")
	}
	if err := validateDistinctExitIP("not-an-ip", "198.51.100.20"); err == nil {
		t.Fatal("invalid exit IP accepted")
	}
	if err := validateDistinctExitIP("203.0.113.10", ""); err == nil {
		t.Fatal("missing direct IP accepted")
	}
}

func TestSingBoxInstallerCandidatesFindsInstallerInstalledByS1TStart(t *testing.T) {
	got := singBoxInstallerCandidates("/usr/local/bin/ravanreverse")
	if len(got) < 3 {
		t.Fatalf("installer candidates = %#v; want canonical, legacy and executable-relative paths", got)
	}
	if got[0] != "/usr/local/lib/shah-tunnel/install-sing-box.sh" {
		t.Fatalf("first installer candidate = %q; want S1T-START.sh STATE_DIR path", got[0])
	}
	if got[1] != "/var/lib/shah-tunnel/install-sing-box.sh" {
		t.Fatalf("second installer candidate = %q; want legacy compatibility path", got[1])
	}
	if got[2] != "/usr/local/bin/scripts/install-sing-box.sh" {
		t.Fatalf("source fallback = %q; want executable-relative scripts path", got[2])
	}
}

func TestSingBoxInstallerCandidatesDeduplicatesPaths(t *testing.T) {
	got := singBoxInstallerCandidates("/usr/local/lib/shah-tunnel/ravanreverse")
	seen := map[string]bool{}
	for _, path := range got {
		if seen[path] {
			t.Fatalf("duplicate installer candidate %q in %#v", path, got)
		}
		seen[path] = true
	}
}
