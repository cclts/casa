package audit

import (
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/event"
)

func TestConvertRecentEventsSerializesFieldsByEventType(t *testing.T) {
	now := time.Now()
	items := []context.ObservedEvent{
		{Type: event.EventOpenat, PID: 1, Path: "/tmp/demo", Flags: 0x241, Mode: 0o666, Addr: "0.0.0.0", Time: now},
		{Type: event.EventExecve, PID: 2, Path: "/bin/sh", Addr: "0.0.0.0", Time: now},
		{Type: event.EventConnect, PID: 3, Addr: "8.8.8.8", Port: 443, Path: "/should/not/appear", Time: now},
		{Type: event.EventExit, PID: 4, TID: 9, Addr: "0.0.0.0", Time: now},
	}

	got := convertRecentEvents(items)
	if got[0].Addr != nil {
		t.Fatalf("expected openat event not to serialize addr")
	}
	if got[1].Addr != nil {
		t.Fatalf("expected execve event not to serialize addr")
	}
	if got[2].Path != nil {
		t.Fatalf("expected connect event not to serialize path")
	}
	if got[3].Addr != nil || got[3].Path != nil || got[3].Flags != nil {
		t.Fatalf("expected exit event to keep only common fields")
	}
	if got[3].TID != 9 {
		t.Fatalf("expected exit event to retain tid for thread/process disambiguation, got %d", got[3].TID)
	}
}
