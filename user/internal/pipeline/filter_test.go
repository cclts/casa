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
	}

	for _, evt := range cases {
		if ShouldIngestIntoContext(evt) {
			t.Fatalf("expected %q to be filtered from context ingestion", evt.Path)
		}
	}
}

func TestShouldIngestIntoContextKeepsRegularOpens(t *testing.T) {
	evt := event.Event{Type: event.EventOpenat, Path: "/tmp/openclaw-eval/backdoor.sh"}
	if !ShouldIngestIntoContext(evt) {
		t.Fatalf("expected regular open to remain eligible for context ingestion")
	}
}
