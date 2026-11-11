package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildXrayWarpConfigCreatesIsolatedInboundAndRoute(t *testing.T) {
	source := map[string]any{
		"log": map[string]any{"access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "warning"},
		"inbounds": []any{
			map[string]any{
				"tag": "panel-vless", "listen": "0.0.0.0", "port": 2083,
				"protocol":       "vless",
				"settings":       map[string]any{"clients": []any{map[string]any{"id": "00000000-0000-0000-0000-000000000000"}}, "decryption": "none"},
				"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"dest": "www.example.com:443"}},
			},
			map[string]any{"tag": "other", "listen": "127.0.0.1", "port": 2096, "protocol": "socks"},
		},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{}}},
		"routing":   map[string]any{"rules": []any{map[string]any{"type": "field", "outboundTag": "direct", "domain": []any{"geosite:category-ads-all"}}}},
	}

	encoded, err := buildXrayWarpConfig(source, 2083, 32083, "shah-warp-in-test", "shah-warp-egress-test")
	if err != nil {
		t.Fatalf("buildXrayWarpConfig: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal generated config: %v", err)
	}

	inbounds := got["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("sidecar should contain exactly one cloned inbound, got %d", len(inbounds))
	}
	inbound := inbounds[0].(map[string]any)
	if inbound["listen"] != "127.0.0.1" || int(inbound["port"].(float64)) != 32083 || inbound["tag"] != "shah-warp-in-test" {
		t.Fatalf("sidecar inbound was not isolated: %#v", inbound)
	}
	if inbound["protocol"] != "vless" || inbound["streamSettings"] == nil || inbound["settings"] == nil {
		t.Fatalf("original client protocol/security settings were not preserved: %#v", inbound)
	}

	outbounds := got["outbounds"].([]any)
	if len(outbounds) != 2 {
		t.Fatalf("expected original outbound plus WARP SOCKS outbound, got %d", len(outbounds))
	}
	warpOutbound := outbounds[1].(map[string]any)
	if warpOutbound["tag"] != "shah-warp-egress-test" || warpOutbound["protocol"] != "socks" {
		t.Fatalf("WARP outbound missing: %#v", warpOutbound)
	}
	settings := warpOutbound["settings"].(map[string]any)
	servers := settings["servers"].([]any)
	server := servers[0].(map[string]any)
	if server["address"] != "127.0.0.1" || int(server["port"].(float64)) != 40000 {
		t.Fatalf("unexpected WARP SOCKS endpoint: %#v", server)
	}

	routing := got["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["outboundTag"] != "shah-warp-egress-test" {
		t.Fatalf("WARP routing rule must be evaluated before existing rules: %#v", first)
	}
	if strings.Contains(string(encoded), "/var/log/xray/access.log") || strings.Contains(string(encoded), "/var/log/xray/error.log") {
		t.Fatal("sidecar must not write into the panel's original Xray log files")
	}

	originalInbound := source["inbounds"].([]any)[0].(map[string]any)
	if originalInbound["listen"] != "0.0.0.0" || int(originalInbound["port"].(int)) != 2083 {
		t.Fatal("source Xray config was modified while building sidecar")
	}
}

func TestBuildXrayWarpConfigRejectsMissingInbound(t *testing.T) {
	_, err := buildXrayWarpConfig(map[string]any{"inbounds": []any{}, "outbounds": []any{}}, 2083, 32083, "in", "out")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing inbound error, got %v", err)
	}
}

func TestValidateXrayWarpMappingRequiresLoopbackAndAcceptsUnpreparedSidecar(t *testing.T) {
	mapping := PortMapping{ID: "warp", Target: "127.0.0.1:2083", TargetEgress: warpXrayEgress}
	if err := validateXrayWarpMapping(mapping); err != nil {
		t.Fatalf("unprepared wizard mapping should validate before sidecar creation: %v", err)
	}
	mapping.Target = "203.0.113.10:2083"
	if err := validateXrayWarpMapping(mapping); err == nil {
		t.Fatal("non-loopback target must be rejected for isolated Xray WARP sidecar")
	}
}

func TestPrepareAgentTargetOverridesUsesSidecarOnlyInMemory(t *testing.T) {
	cfg := Config{Role: "agent", Ports: []PortMapping{{ID: "warp", Target: "127.0.0.1:2083", TargetEgress: warpXrayEgress, WarpTarget: "127.0.0.1:32083"}}}
	got, err := prepareAgentTargetOverrides(cfg)
	if err != nil {
		t.Fatalf("prepareAgentTargetOverrides: %v", err)
	}
	if got.Ports[0].Target != "127.0.0.1:32083" {
		t.Fatalf("runtime target did not switch to sidecar: %s", got.Ports[0].Target)
	}
	if cfg.Ports[0].Target != "127.0.0.1:2083" {
		t.Fatalf("saved/source config was mutated: %s", cfg.Ports[0].Target)
	}
}

func TestValidateWARPIPResponse(t *testing.T) {
	if err := validateWARPIPResponse([]byte("203.0.113.20\n"), "IPv4"); err != nil {
		t.Fatalf("valid IPv4 response rejected: %v", err)
	}
	if err := validateWARPIPResponse([]byte("2001:db8::20\n"), "IPv6"); err != nil {
		t.Fatalf("valid IPv6 response rejected: %v", err)
	}
	if err := validateWARPIPResponse([]byte("2001:db8::20"), "IPv4"); err == nil {
		t.Fatal("IPv6 response was accepted for IPv4 check")
	}
	if err := validateWARPIPResponse([]byte("203.0.113.20"), "IPv6"); err == nil {
		t.Fatal("IPv4 response was accepted for IPv6 check")
	}
	if err := validateWARPIPResponse([]byte("not-an-ip"), "IPv6"); err == nil {
		t.Fatal("invalid IP response was accepted")
	}
}
