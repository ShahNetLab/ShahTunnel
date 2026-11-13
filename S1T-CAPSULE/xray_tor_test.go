package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildXrayTorConfigIsolatesTCPAndBlocksUDP(t *testing.T) {
	original := []byte(`{
  "inbounds": [
    {"tag":"xui-vless","listen":"0.0.0.0","port":2083,"protocol":"vless","settings":{"clients":[{"id":"test-id"}]}}
  ],
  "outbounds": [
    {"tag":"direct","protocol":"freedom"}
  ],
  "routing": {"rules": []}
}`)
	before := append([]byte(nil), original...)
	generated, bindings, outTag, err := buildXrayTorConfig(original, "tor-profile", "127.0.0.1:19050", []PortMapping{{ID: "main", Target: "127.0.0.1:2083"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, before) {
		t.Fatal("source X-UI config bytes were mutated")
	}
	if len(bindings) != 1 || bindings[0].OriginalTarget != "127.0.0.1:2083" || bindings[0].TorTarget == bindings[0].OriginalTarget {
		t.Fatalf("unexpected isolated Tor binding: %#v", bindings)
	}
	var got map[string]any
	if err := json.Unmarshal(generated, &got); err != nil {
		t.Fatal(err)
	}
	inbounds := got["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("sidecar inbound count=%d; want one cloned inbound", len(inbounds))
	}
	clone := inbounds[0].(map[string]any)
	if clone["listen"] != "127.0.0.1" || clone["tag"] != bindings[0].InboundTag {
		t.Fatalf("Tor clone is not loopback-only/tagged: %#v", clone)
	}
	outbounds := got["outbounds"].([]any)
	foundSocks, foundBlock, foundDirect := false, false, false
	blockTag := "s1t-tor-tor-profile-udp-block"
	for _, raw := range outbounds {
		x := raw.(map[string]any)
		switch x["tag"] {
		case outTag:
			foundSocks = x["protocol"] == "socks"
		case blockTag:
			foundBlock = x["protocol"] == "blackhole"
		case "direct":
			foundDirect = true
		}
	}
	if !foundSocks || !foundBlock || !foundDirect {
		t.Fatalf("sidecar must preserve original outbound and add SOCKS+UDP blackhole: %#v", outbounds)
	}
	rules := got["routing"].(map[string]any)["rules"].([]any)
	if len(rules) < 5 {
		t.Fatalf("not enough ordered Tor routing rules: %#v", rules)
	}
	if rules[0].(map[string]any)["outboundTag"] != "s1t-tor-tor-profile-dns-out" {
		t.Fatalf("DNS hijack must run before protocol routing: %#v", rules[0])
	}
	if rules[1].(map[string]any)["outboundTag"] != outTag {
		t.Fatalf("DNS resolver traffic must use Tor SOCKS: %#v", rules[1])
	}
	if rules[2].(map[string]any)["network"] != "tcp" || rules[2].(map[string]any)["outboundTag"] != outTag {
		t.Fatalf("cloned TCP traffic must use Tor: %#v", rules[2])
	}
	if rules[3].(map[string]any)["network"] != "udp" || rules[3].(map[string]any)["outboundTag"] != blockTag {
		t.Fatalf("cloned UDP traffic must be blocked, not sent Direct: %#v", rules[3])
	}
	if rules[4].(map[string]any)["outboundTag"] != blockTag {
		t.Fatalf("unmatched protocols on the cloned inbound must fail closed: %#v", rules[4])
	}
	if _, ok := got["api"]; ok {
		t.Fatal("X-UI API section must not be copied into the sidecar")
	}
}

func TestXrayTorManagedPathsAndUnitAreRestricted(t *testing.T) {
	if _, err := xrayTorUnitPath("x-ui.service"); err == nil {
		t.Fatal("must not manage X-UI systemd unit")
	}
	if _, err := xrayTorConfigDirectory("/usr/local/x-ui/bin/config.json"); err == nil {
		t.Fatal("must not remove or alter X-UI config directory")
	}
	if dir, err := xrayTorConfigDirectory("/etc/ravanreverse/xray-tor/profile-s/config.json"); err != nil || dir != "/etc/ravanreverse/xray-tor/profile-s" {
		t.Fatalf("unexpected managed config directory %q, error=%v", dir, err)
	}
	runtime := xrayRuntime{Binary: "/usr/local/x-ui/bin/xray-linux-amd64", CWD: "/usr/local/x-ui/bin", Service: "x-ui.service"}
	service := xrayTorServiceName("profile-s")
	unit, err := renderXrayTorUnit(runtime, "/etc/ravanreverse/xray-tor/profile-s/config.json", service)
	if err != nil {
		t.Fatal(err)
	}
	unitText := string(unit)
	for _, want := range []string{
		"ExecStart=\"/usr/local/x-ui/bin/xray-linux-amd64\" run -config \"/etc/ravanreverse/xray-tor/profile-s/config.json\"",
		"WorkingDirectory=/usr/local/x-ui/bin",
		"Restart=on-failure",
		"After=network-online.target ravanreverse@profile-s.service",
		"PartOf=ravanreverse@profile-s.service",
		"NoNewPrivileges=yes",
		"ProtectSystem=full",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
	} {
		if !strings.Contains(unitText, want) {
			t.Fatalf("Tor sidecar unit missing %q:\n%s", want, unitText)
		}
	}
	if strings.Contains(unitText, "ProtectHome=yes") || strings.Contains(unitText, "PrivateTmp=yes") {
		t.Fatalf("Tor sidecar must preserve access to Xray certificate paths, including paths under /root or /tmp: %s", unitText)
	}
	if strings.Contains(unitText, "x-ui.service") || strings.Contains(unitText, "ExecStart=/bin/sh") {
		t.Fatalf("Tor sidecar must not restart X-UI or run through a shell: %s", unitText)
	}
}

func TestRollbackFailedTorAgentSetupRefusesForeignPaths(t *testing.T) {
	foreign := filepath.Join(t.TempDir(), "keep.json")
	if err := os.WriteFile(foreign, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	err := rollbackFailedTorAgentSetup(foreign, Config{Name: "profile-s", TorDataDir: filepath.Join(torDataRoot, "profile-s")})
	if err == nil {
		t.Fatal("rollback accepted a config path outside the ShahTunnel tunnel directory")
	}
	data, readErr := os.ReadFile(foreign)
	if readErr != nil || string(data) != "keep" {
		t.Fatalf("foreign config file was changed: data=%q err=%v", data, readErr)
	}
}
