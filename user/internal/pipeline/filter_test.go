package pipeline

import (
	"testing"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/rules"
)

func TestShouldIngestIntoContextFiltersRuntimeNoise(t *testing.T) {
	cases := []event.Event{
		{Type: event.EventOpenat, Path: ""},
		{Type: event.EventOpenat, Path: "/proc/self/status"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/lib/node_modules/openclaw/package.json"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.openclaw/agents/main/sessions/foo.json"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.bashrc"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.env"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.curlrc"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.config/curlrc"},
		{Type: event.EventOpenat, Path: "/etc/hosts"},
		{Type: event.EventOpenat, Path: "/etc/nsswitch.conf"},
		{Type: event.EventOpenat, Path: "/etc/passwd"},
		{Type: event.EventOpenat, Path: "/etc/gnutls/config"},
		{Type: event.EventOpenat, Path: "/var/lib/crypto-config/profiles/current/gnutls.conf"},
		{Type: event.EventOpenat, Path: "/usr/lib/ssl/openssl.cnf"},
		{Type: event.EventOpenat, Path: "/tmp/openclaw/openclaw-2026-05-19.log"},
	}

	for _, evt := range cases {
		if ShouldIngestIntoContext(evt) {
			t.Fatalf("expected %q to be filtered from context ingestion", evt.Path)
		}
	}
}

func TestShouldIngestIntoContextFiltersIgnorableConnectNoise(t *testing.T) {
	cases := []event.Event{
		{Type: event.EventConnect, Addr: "142.250.26.95", Port: 0},
		{Type: event.EventConnect, Addr: "", Port: 443},
		{Type: event.EventConnect, Addr: "0.0.0.0"},
		{Type: event.EventConnect, Addr: "127.0.0.53", Port: 53},
		{Type: event.EventConnect, Addr: "127.0.0.1", Port: 11434},
	}

	for _, evt := range cases {
		if ShouldIngestIntoContext(evt) {
			t.Fatalf("expected connect noise %+v to be filtered from context ingestion", evt)
		}
	}
}

func TestShouldIngestIntoContextAllowsConfiguredLoopbackPorts(t *testing.T) {
	ConfigureFilters(rules.AnalysisConfig{
		AllowedLoopbackPorts: []uint16{18000},
	})
	defer ConfigureFilters(rules.AnalysisConfig{})

	cases := []event.Event{
		{Type: event.EventConnect, Addr: "127.0.0.1", Port: 18000},
	}

	for _, evt := range cases {
		if !ShouldIngestIntoContext(evt) {
			t.Fatalf("expected configured loopback connect %+v to remain eligible for context ingestion", evt)
		}
	}
}

func TestShouldIngestIntoContextFiltersConfiguredIgnoredConnectIPs(t *testing.T) {
	ConfigureFilters(rules.AnalysisConfig{
		IgnoredConnectIPs: []string{"149.154.166.110"},
	})
	defer ConfigureFilters(rules.AnalysisConfig{})

	evt := event.Event{Type: event.EventConnect, Addr: "149.154.166.110", Port: 443}
	if ShouldIngestIntoContext(evt) {
		t.Fatalf("expected configured ignored connect ip to be filtered from context ingestion")
	}
}

func TestShouldIngestIntoContextKeepsRegularOpens(t *testing.T) {
	evt := event.Event{Type: event.EventOpenat, Path: "/tmp/openclaw-eval/backdoor.sh"}
	if !ShouldIngestIntoContext(evt) {
		t.Fatalf("expected regular open to remain eligible for context ingestion")
	}
}

func TestShouldIngestIntoContextFiltersTransparentRoutineExecWithProgramArgv(t *testing.T) {
	evt := event.Event{
		Type: event.EventExecve,
		Path: "/usr/bin/ip",
		Args: []string{"ip", "neigh", "show"},
	}
	if ShouldIngestIntoContext(evt) {
		t.Fatalf("expected ip neigh show execve to be filtered as transparent routine exec")
	}
}
