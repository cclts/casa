package pipeline

import (
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

func TestIsPendingShellExecve(t *testing.T) {
	cases := []struct {
		event event.Event
		want  bool
	}{
		{event: event.Event{Type: event.EventExecve, Path: "/bin/sh"}, want: true},
		{event: event.Event{Type: event.EventExecve, Path: "/bin/bash", Args: []string{"bash"}}, want: true},
		{event: event.Event{Type: event.EventExecve, Path: "/bin/sh", Args: []string{"sh", "-c", "curl"}}, want: false},
		{event: event.Event{Type: event.EventExecve, Path: "/usr/bin/curl"}, want: false},
	}

	for _, tc := range cases {
		if got := isPendingShellExecve(tc.event); got != tc.want {
			t.Fatalf("isPendingShellExecve(%+v) = %v, want %v", tc.event, got, tc.want)
		}
	}
}

func TestPendingShellWrapperPromotesMeaningfulLaterEvent(t *testing.T) {
	pending := newPendingShellWrappers()
	tracker := process.NewTracker()
	sessionID := process.SessionID(7)
	now := time.Now()

	tracker.Add(100, 50, 1, true)
	pending.Add(sessionID, event.Event{
		Type: event.EventExecve,
		PID:  100,
		PPID: 50,
		Path: "/bin/sh",
		Time: now,
	})

	if !pending.PromoteIfMeaningful(sessionID, event.Event{
		Type: event.EventConnect,
		PID:  100,
		PPID: 50,
		Addr: "8.8.8.8",
		Port: 443,
		Time: now.Add(time.Second),
	}, tracker) {
		t.Fatalf("expected meaningful connect to promote pending shell")
	}

	info, ok := tracker.GetInfo(100)
	if !ok {
		t.Fatalf("expected tracked shell to remain present")
	}
	if info.Transparent {
		t.Fatalf("expected promoted shell to become visible in lineage")
	}
}

func TestPendingShellWrapperKeepsNoiseHidden(t *testing.T) {
	pending := newPendingShellWrappers()
	tracker := process.NewTracker()
	sessionID := process.SessionID(8)
	now := time.Now()

	tracker.Add(100, 50, 1, true)
	pending.Add(sessionID, event.Event{
		Type: event.EventExecve,
		PID:  100,
		PPID: 50,
		Path: "/bin/sh",
		Time: now,
	})

	if pending.PromoteIfMeaningful(sessionID, event.Event{
		Type: event.EventOpenat,
		PID:  100,
		Path: "/etc/hosts",
		Time: now.Add(time.Second),
	}, tracker) {
		t.Fatalf("expected routine open noise not to promote pending shell")
	}
}
