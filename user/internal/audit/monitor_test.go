package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/context"
)

func TestRecordSessionSnapshotWritesLifecycleReasonAndClearsClosedSession(t *testing.T) {
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "sessions.log")
	m, err := NewMonitor(
		filepath.Join(dir, "events.log"),
		sessionPath,
		filepath.Join(dir, "audit.log"),
		filepath.Join(dir, "alert.log"),
	)
	if err != nil {
		t.Fatalf("new monitor: %v", err)
	}

	now := time.Now()
	raw := context.SessionSnapshot{
		ID:        1,
		CreatedAt: now.Add(-time.Second),
		UpdatedAt: now,
		ClosedAt:  now,
	}
	if err := m.RecordSessionSnapshot(raw, "session_closed", now); err != nil {
		t.Fatalf("record session snapshot: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("close monitor: %v", err)
	}

	lines := readNonEmptyLines(t, sessionPath)
	if len(lines) != 1 {
		t.Fatalf("expected exactly one lifecycle snapshot, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `"reason":"session_closed"`) {
		t.Fatalf("expected session_closed reason, got %s", lines[0])
	}
	if strings.Contains(lines[0], "alert_threshold_crossed") {
		t.Fatalf("unexpected alert-driven session log: %s", lines[0])
	}
}

func TestFlushSessionsLockedWritesPeriodicSnapshots(t *testing.T) {
	dir := t.TempDir()
	sessionPath := filepath.Join(dir, "sessions.log")
	m, err := NewMonitor(
		filepath.Join(dir, "events.log"),
		sessionPath,
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
	m.mu.Lock()
	m.sessions[7] = &sessionAggregate{ID: 7}
	m.rawSessions[7] = context.SessionSnapshot{
		ID:        7,
		CreatedAt: now.Add(-time.Second),
		UpdatedAt: now,
	}
	m.flushSessionsLocked("periodic_flush", false)
	m.mu.Unlock()

	lines := readNonEmptyLines(t, sessionPath)
	if len(lines) == 0 {
		t.Fatalf("expected periodic flush to write a session snapshot")
	}
	if !strings.Contains(lines[0], `"reason":"periodic_flush"`) {
		t.Fatalf("expected periodic_flush reason, got %s", lines[0])
	}
}

func readNonEmptyLines(t *testing.T, path string) []string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return lines
}
