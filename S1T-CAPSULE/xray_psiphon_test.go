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
