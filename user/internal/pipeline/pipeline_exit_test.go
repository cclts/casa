package pipeline

import (
	"testing"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

func TestNonLeaderThreadExitDoesNotRemoveTrackedProcess(t *testing.T) {
	tracker := process.NewTracker()
	tracker.Add(100, 1, 0, false)
	tracker.AddRoot(100)

	threadExit := event.Event{Type: event.EventExit, PID: 100, TID: 101}
	if threadExit.Type == event.EventExit && threadExit.PID == threadExit.TID {
		tracker.Remove(threadExit.PID)
	}
	if !tracker.Exists(100) {
		t.Fatalf("expected non-leader thread exit not to remove tracked process")
	}

	leaderExit := event.Event{Type: event.EventExit, PID: 100, TID: 100}
	if leaderExit.Type == event.EventExit && leaderExit.PID == leaderExit.TID {
		tracker.Remove(leaderExit.PID)
	}
	if tracker.Exists(100) {
		t.Fatalf("expected leader exit to remove tracked process")
	}
}
