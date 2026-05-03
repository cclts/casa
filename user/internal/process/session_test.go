package process

import (
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/event"
)

func TestIsOpenClawCLIInvocationRequiresMatchingNodeAndOpenClawPaths(t *testing.T) {
	e := event.Event{
		Type: event.EventExecve,
		Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node",
		Args: []string{
			"node",
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/openclaw",
			"agent",
			"--agent",
			"main",
			"-m",
			"hey",
		},
	}

	if !isOpenClawCLIInvocation(e) {
		t.Fatalf("expected matching node/openclaw runtime paths to start a session")
	}
}

func TestIsOpenClawCLIInvocationAllowsRuntimeSelfReexecShape(t *testing.T) {
	e := event.Event{
		Type: event.EventExecve,
		Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node",
		Args: []string{
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node",
			"--disable-warning=ExperimentalWarning",
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/openclaw",
			"agent",
			"--agent",
			"main",
			"-m",
			"hey",
		},
	}

	if !isOpenClawCLIInvocation(e) {
		t.Fatalf("expected runtime self-reexec shape to still count as openclaw cli invocation")
	}
}

func TestIsOpenClawCLIInvocationRejectsMismatchedRuntimePaths(t *testing.T) {
	e := event.Event{
		Type: event.EventExecve,
		Path: "/home/ubuntu/.pyenv/bin/node",
		Args: []string{
			"node",
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/openclaw",
			"agent",
			"--agent",
			"main",
			"-m",
			"hey",
		},
	}

	if isOpenClawCLIInvocation(e) {
		t.Fatalf("expected mismatched node/openclaw runtime paths not to start a session")
	}
}

func TestObserveExecveStartsOnlyOneActiveSession(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Now()

	first := event.Event{
		Type: event.EventExecve,
		PID:  271660,
		PPID: 271658,
		Time: now,
		Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node",
		Args: []string{
			"node",
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/openclaw",
			"agent",
			"--agent",
			"main",
			"-m",
			"hey",
		},
	}
	second := event.Event{
		Type: event.EventExecve,
		PID:  271671,
		PPID: 271660,
		Time: now.Add(100 * time.Millisecond),
		Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node",
		Args: []string{
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node",
			"--disable-warning=ExperimentalWarning",
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/openclaw",
			"agent",
			"--agent",
			"main",
			"-m",
			"hey",
		},
	}

	tracker.ObserveExecve(first)
	tracker.ObserveExecve(second)

	if got := len(tracker.sessions); got != 1 {
		t.Fatalf("expected exactly one active session, got %d", got)
	}

	sess, ok := tracker.activeSessionLocked(second.Time)
	if !ok {
		t.Fatalf("expected active session to remain available")
	}
	if sess.SessionPID != first.PID {
		t.Fatalf("expected outer successful launcher pid to own the session, got %d", sess.SessionPID)
	}
}

func TestObserveExitRequiresLeaderThreadToCloseSession(t *testing.T) {
	tracker := NewSessionTracker()
	now := time.Now()

	start := event.Event{
		Type: event.EventExecve,
		PID:  296908,
		PPID: 296900,
		TID:  296908,
		Time: now,
		Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/bin/node",
		Args: []string{
			"node",
			"/home/ubuntu/.nvm/versions/node/v24.14.1/bin/openclaw",
			"agent",
			"--agent",
			"main",
			"-m",
			"hey",
		},
	}
	tracker.ObserveExecve(start)

	threadExit := event.Event{
		Type: event.EventExit,
		PID:  296908,
		TID:  296931,
		Time: now.Add(time.Second),
	}
	tracker.ObserveExit(threadExit)

	sess, ok := tracker.activeSessionLocked(threadExit.Time)
	if !ok {
		t.Fatalf("expected session to remain active after non-leader thread exit")
	}
	if !sess.ClosingAt.IsZero() {
		t.Fatalf("expected non-leader thread exit not to start closing window")
	}

	leaderExit := event.Event{
		Type: event.EventExit,
		PID:  296908,
		TID:  296908,
		Time: now.Add(2 * time.Second),
	}
	tracker.ObserveExit(leaderExit)

	sess, ok = tracker.activeSessionLocked(leaderExit.Time)
	if !ok {
		t.Fatalf("expected session to still be visible during grace period")
	}
	if sess.ClosingAt.IsZero() {
		t.Fatalf("expected leader exit to start closing window")
	}
}
