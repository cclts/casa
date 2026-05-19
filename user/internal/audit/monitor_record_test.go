package audit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/rules"
)

func TestRecordReportsAuditAndAlertEmission(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(
		filepath.Join(dir, "events.log"),
		"",
		filepath.Join(dir, "sessions.log"),
		filepath.Join(dir, "audit.log"),
		filepath.Join(dir, "alert.log"),
	)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	defer func() {
		_ = m.Close()
	}()

	now := time.Now()
	e := event.Event{
		Type:      event.EventConnect,
		PID:       100,
		TID:       100,
		PPID:      50,
		UID:       1000,
		Comm:      "curl",
		Addr:      "1.2.3.4",
		Port:      443,
		Time:      now,
		TimeHuman: now.Format(time.RFC3339Nano),
	}
	raw := context.SessionSnapshot{
		ID:        7,
		CreatedAt: now.Add(-time.Second),
		UpdatedAt: now,
	}
	result := decision.Result{
		Score:          9,
		Action:         decision.ActionAlert,
		Triggered:      []rules.TriggeredRule{{Name: "connect_then_exec", Expr: "history.connect_then_exec", Weight: 9}},
		LogThreshold:   4,
		AlertThreshold: 9,
	}

	outcome, err := m.Record(e, &raw, &result)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if !outcome.AuditEmitted {
		t.Fatalf("expected audit emitted")
	}
	if !outcome.AlertEmitted {
		t.Fatalf("expected alert emitted")
	}
}

func TestRecordDoesNotReportThresholdEmissionWithoutTriggeredRules(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(
		filepath.Join(dir, "events.log"),
		"",
		filepath.Join(dir, "sessions.log"),
		filepath.Join(dir, "audit.log"),
		filepath.Join(dir, "alert.log"),
	)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}
	defer func() {
		_ = m.Close()
	}()

	now := time.Now()
	e := event.Event{
		Type:      event.EventExecve,
		PID:       100,
		TID:       100,
		PPID:      50,
		UID:       1000,
		Comm:      "bash",
		Path:      "/bin/bash",
		Time:      now,
		TimeHuman: now.Format(time.RFC3339Nano),
	}
	raw := context.SessionSnapshot{
		ID:        9,
		CreatedAt: now.Add(-time.Second),
		UpdatedAt: now,
	}
	result := decision.Result{
		Score:          99,
		Action:         decision.ActionIgnore,
		LogThreshold:   4,
		AlertThreshold: 9,
	}

	outcome, err := m.Record(e, &raw, &result)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if outcome.AuditEmitted {
		t.Fatalf("expected no audit emitted")
	}
	if outcome.AlertEmitted {
		t.Fatalf("expected no alert emitted")
	}
}
