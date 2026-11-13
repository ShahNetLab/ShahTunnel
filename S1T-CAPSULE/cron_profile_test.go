package main

import (
	"strings"
	"testing"
)

func TestRestartPathsAreIsolatedPerProfile(t *testing.T) {
	a, err := restartPathsForService("ravanreverse@s")
	if err != nil {
		t.Fatal(err)
	}
	b, err := restartPathsForService("ravanreverse@sh")
	if err != nil {
		t.Fatal(err)
	}
	if a.config == b.config || a.state == b.state || a.cron == b.cron || a.script == b.script || a.lock == b.lock {
		t.Fatal("different profiles must have independent cron/config/state/script/lock paths")
	}
	body := restartCronScriptForProfile(a)
	if !strings.Contains(body, `SERVICE="ravanreverse@s.service"`) || strings.Contains(body, "ravanreverse@sh.service") {
		t.Fatalf("cron script for profile s is not isolated: %s", body)
	}
	if strings.Contains(body, "list-units") || strings.Contains(body, "ravanreverse.service") {
		t.Fatal("profile cron script must not restart all or legacy tunnel services")
	}
}

func TestRestartPathsRejectUnmanagedServices(t *testing.T) {
	for _, name := range []string{"cron.service", "ravanreverse@bad/name", "ravanreverse@"} {
		if _, err := restartPathsForService(name); err == nil {
			t.Fatalf("service %q should be rejected", name)
		}
	}
}
