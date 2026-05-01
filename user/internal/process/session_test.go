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
		t.Fatalf("expected matching node/openclaw runtime paths to start a session")
	}
}

func TestIsOpenClawCLIInvocationRejectsOuterLauncherShape(t *testing.T) {
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

	if isOpenClawCLIInvocation(e) {
		t.Fatalf("expected outer launcher shape not to start a session")
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
	if sess.SessionPID != second.PID {
		t.Fatalf("expected runtime self-reexec pid to own the session, got %d", sess.SessionPID)
	}
}
