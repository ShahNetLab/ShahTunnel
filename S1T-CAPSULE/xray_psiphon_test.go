package main

import (
	"strings"
	"testing"
)

func TestXrayPsiphonUnitOwnershipAllowsOnlyExactProfileService(t *testing.T) {
	runtime := xrayRuntime{Binary: "/usr/local/bin/xray", CWD: "/usr/local/bin"}
	service := "shah-tunnel-xray-psiphon-s.service"
	configPath := "/etc/ravanreverse/xray-psiphon/s/config.json"
	unit, err := renderXrayPsiphonUnit(runtime, configPath, service)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "Managed-By: ShahTunnel 5.0.0") {
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
