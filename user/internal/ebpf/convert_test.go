package ebpf

import (
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/event"
)

func TestToEventConvertsFields(t *testing.T) {
	oldTimeFromKtime := eventTimeFromKtime
	oldFormatEventTime := formatEventTime
	defer func() {
		eventTimeFromKtime = oldTimeFromKtime
		formatEventTime = oldFormatEventTime
	}()

	eventTimeFromKtime = func(_ uint64) (time.Time, error) {
		return time.Unix(100, 0), nil
	}
	formatEventTime = func(ts time.Time) string {
		return ts.UTC().Format(time.RFC3339Nano)
	}

	raw := Event{
		Tgid:  42,
		Pid:   99,
		Ppid:  7,
		Uid:   501,
		Type:  1,
		Argc:  2,
		Flags: 0x241,
		Mode:  0o755,
		TsNS:  123,
		Daddr: 0x0100007f,
		Dport: 0x5000,
	}
	copy(raw.Comm[:], []byte("bash"))
	copy(raw.Filename[:], []byte("/tmp/demo.sh"))
	copy(raw.Args[0][:], []byte("sh"))
	copy(raw.Args[1][:], []byte("/tmp/demo.sh"))

	got := ToEvent(raw)
	if got.Type != event.EventOpenat {
		t.Fatalf("expected openat event type, got %v", got.Type)
	}
	if got.PID != 42 || got.TID != 99 || got.PPID != 7 || got.UID != 501 {
		t.Fatalf("unexpected pid metadata: %+v", got)
	}
	if got.Addr != "127.0.0.1" || got.Port != 80 {
		t.Fatalf("unexpected network fields: addr=%s port=%d", got.Addr, got.Port)
	}
	if got.Comm != "bash" || got.Path != "/tmp/demo.sh" {
		t.Fatalf("unexpected strings: comm=%q path=%q", got.Comm, got.Path)
	}
	if len(got.Args) != 2 || got.Args[1] != "/tmp/demo.sh" {
		t.Fatalf("unexpected args: %#v", got.Args)
	}
	if got.TimeHuman == "" {
		t.Fatalf("expected formatted event time")
	}
}

func TestMapEventTypeFallbacksToExecve(t *testing.T) {
	if mapEventType(99) != event.EventExecve {
		t.Fatalf("expected unknown event types to default to execve")
	}
}
