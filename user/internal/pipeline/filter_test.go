package pipeline

import (
	"testing"

	"github.com/cclts/casa/user/internal/event"
)

func TestShouldIngestIntoContextFiltersRuntimeNoise(t *testing.T) {
	cases := []event.Event{
		{Type: event.EventOpenat, Path: "/proc/self/status"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/lib/node_modules/openclaw/package.json"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.openclaw/agents/main/sessions/foo.json"},
		{Type: event.EventOpenat, Path: "/home/ubuntu/.bashrc"},
		{Type: event.EventOpenat, Path: "/etc/hosts"},
	}

	for _, evt := range cases {
		if ShouldIngestIntoContext(evt) {
			t.Fatalf("expected %q to be filtered from context ingestion", evt.Path)
		}
	}
}

func TestShouldIngestIntoContextFiltersIgnorableConnectNoise(t *testing.T) {
	cases := []event.Event{
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

func TestShouldIngestIntoContextKeepsRegularOpens(t *testing.T) {
	evt := event.Event{Type: event.EventOpenat, Path: "/tmp/openclaw-eval/backdoor.sh"}
	if !ShouldIngestIntoContext(evt) {
		t.Fatalf("expected regular open to remain eligible for context ingestion")
	}
}
