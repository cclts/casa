package telemetry

import (
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/audit"
	ctxpkg "github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
	"github.com/cclts/casa/user/internal/rules"
)

func TestEventName(t *testing.T) {
	cases := []struct {
		eventType event.EventType
		want      string
	}{
		{event.EventConnect, "network"},
		{event.EventOpenat, "file"},
		{event.EventExecve, "process"},
		{event.EventExit, "exit"},
	}

	for _, tc := range cases {
		got := eventName(event.Event{Type: tc.eventType})
		if got != tc.want {
			t.Fatalf("eventName(%v) = %q, want %q", tc.eventType, got, tc.want)
		}
	}
}

func TestSessionTraceObserveAccumulatesFinalState(t *testing.T) {
	session := &sessionTrace{}

	session.observe(
		event.Event{Type: event.EventConnect},
		ctxpkg.ContextSnapshot{
			History: ctxpkg.HistoricalContext{ConnectThenExec: true},
		},
		decision.Result{
			Score:     4,
			Action:    decision.ActionLog,
			Triggered: []rules.TriggeredRule{{Name: "rule-a"}},
		},
		audit.RecordOutcome{AuditEmitted: true},
	)
	session.observe(
		event.Event{Type: event.EventExecve},
		ctxpkg.ContextSnapshot{
			Execution: ctxpkg.ExecutionChainContext{ShellInChain: true},
		},
		decision.Result{
			Score:     9,
			Action:    decision.ActionAlert,
			Triggered: []rules.TriggeredRule{{Name: "rule-b"}, {Name: "rule-c"}},
		},
		audit.RecordOutcome{AuditEmitted: true, AlertEmitted: true},
	)

	if session.acceptedEvents != 2 {
		t.Fatalf("acceptedEvents = %d, want 2", session.acceptedEvents)
	}
	if session.connectCount != 1 || session.execveCount != 1 {
		t.Fatalf("unexpected event counters: connect=%d execve=%d", session.connectCount, session.execveCount)
	}
	if session.finalScore != 9 {
		t.Fatalf("finalScore = %d, want 9", session.finalScore)
	}
	if session.finalAction != decision.ActionAlert {
		t.Fatalf("finalAction = %q, want %q", session.finalAction, decision.ActionAlert)
	}
	if !session.auditEmitted || !session.alertEmitted {
		t.Fatalf("expected both audit and alert to be marked emitted")
	}
	if !session.finalContext.Execution.ShellInChain {
		t.Fatalf("expected final context to track latest snapshot")
	}
}

func TestTriggeredRuleNamesAndRuleMatchAttributes(t *testing.T) {
	result := decision.Result{
		Score:          6,
		Action:         decision.ActionLog,
		LogThreshold:   4,
		AlertThreshold: 9,
		Triggered: []rules.TriggeredRule{
			{Name: "alpha", Expr: "history.connect_then_exec", Weight: 2},
			{Name: "beta", Expr: "history.sensitive_then_network", Weight: 4},
		},
	}
	snapshot := ctxpkg.ContextSnapshot{
		SessionID: 7,
		Execution: ctxpkg.ExecutionChainContext{DeepChain: true, ShellInChain: true},
		Capability: ctxpkg.CapabilityContext{
			HasDangerousCaps: true,
			DangerousCount:   2,
		},
		History: ctxpkg.HistoricalContext{
			ConnectThenExec:      true,
			SensitiveThenNetwork: true,
		},
	}

	names := triggeredRuleNames(result.Triggered)
	if len(names) != 2 || names[0] != "alpha" || names[1] != "beta" {
		t.Fatalf("unexpected triggeredRuleNames: %#v", names)
	}

	attrs := ruleMatchAttributes(snapshot, result, result.Triggered[0])
	if len(attrs) == 0 {
		t.Fatalf("expected ruleMatchAttributes to include telemetry fields")
	}
	sessionAttrs := sessionContextAttributes(snapshot)
	if len(sessionAttrs) == 0 {
		t.Fatalf("expected sessionContextAttributes to include context fields")
	}
}

func TestEventAttributesSpecializeByEventType(t *testing.T) {
	now := time.Now()
	connectAttrs := eventAttributes(process.SessionID(3), event.Event{
		Type: event.EventConnect,
		PID:  100,
		TID:  100,
		PPID: 50,
		UID:  1000,
		Comm: "curl",
		Addr: "1.2.3.4",
		Port: 443,
		Time: now,
	})
	openAttrs := eventAttributes(process.SessionID(3), event.Event{
		Type:  event.EventOpenat,
		PID:   100,
		TID:   100,
		PPID:  50,
		UID:   1000,
		Comm:  "bash",
		Path:  "/tmp/demo.txt",
		Flags: 1,
		Mode:  420,
		Time:  now,
	})

	if len(connectAttrs) == 0 || len(openAttrs) == 0 {
		t.Fatalf("expected event attributes for connect and open events")
	}
}
