package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cclts/care-go/user/internal/context"
	"github.com/cclts/care-go/user/internal/decision"
	"github.com/cclts/care-go/user/internal/event"
)

// Monitor owns the append-only audit sinks used for routine logs and high-risk alerts.
type Monitor struct {
	mu        sync.Mutex
	logFile   *os.File
	alertFile *os.File
}

// Record is the JSONL payload written to disk for every non-ignored decision.
type Record struct {
	Timestamp time.Time       `json:"timestamp"`
	SessionID uint32          `json:"session_id"`
	TargetPID uint32          `json:"target_pid"`
	Event     EventRecord     `json:"event"`
	Context   context.Context `json:"context"`
	Decision  DecisionRecord  `json:"decision"`
}

// EventRecord stores the normalized event fields that triggered evaluation.
type EventRecord struct {
	Type string   `json:"type"`
	PID  uint32   `json:"pid"`
	PPID uint32   `json:"ppid"`
	UID  uint32   `json:"uid"`
	Comm string   `json:"comm"`
	Path string   `json:"path,omitempty"`
	Args []string `json:"args,omitempty"`
	Addr string   `json:"addr,omitempty"`
	Port uint32   `json:"port,omitempty"`
}

// DecisionRecord stores the scoring output that explains why a record was logged.
type DecisionRecord struct {
	Action         decision.Action `json:"action"`
	Score          int             `json:"score"`
	LogThreshold   int             `json:"log_threshold"`
	AlertThreshold int             `json:"alert_threshold"`
	Triggered      interface{}     `json:"triggered_rules"`
}

// NewMonitor opens append-only audit and alert log files.
func NewMonitor(logPath, alertPath string) (*Monitor, error) {
	logFile, err := openLogFile(logPath)
	if err != nil {
		return nil, err
	}

	alertFile, err := openLogFile(alertPath)
	if err != nil {
		_ = logFile.Close()
		return nil, err
	}

	return &Monitor{
		logFile:   logFile,
		alertFile: alertFile,
	}, nil
}

// Close releases any open file handles owned by the monitor.
func (m *Monitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	if m.logFile != nil {
		if err := m.logFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if m.alertFile != nil {
		if err := m.alertFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

// Record writes the full decision snapshot to the audit log and mirrors alerts
// to the dedicated alert log for easier triage.
func (m *Monitor) Record(e event.Event, ctx context.Context, result decision.Result) error {
	if result.Action == decision.ActionIgnore {
		return nil
	}

	record := Record{
		Timestamp: time.Now().UTC(),
		SessionID: ctx.SessionID,
		TargetPID: ctx.TargetPID,
		Event: EventRecord{
			Type: e.Type.String(),
			PID:  e.PID,
			PPID: e.PPID,
			UID:  e.UID,
			Comm: e.Comm,
			Path: e.Path,
			Args: append([]string(nil), e.Args...),
			Addr: e.Addr,
			Port: e.Port,
		},
		Context: ctx,
		Decision: DecisionRecord{
			Action:         result.Action,
			Score:          result.Score,
			LogThreshold:   result.LogThreshold,
			AlertThreshold: result.AlertThreshold,
			Triggered:      result.Triggered,
		},
	}

	line, err := json.Marshal(record)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := m.logFile.Write(append(line, '\n')); err != nil {
		return err
	}

	if result.Action == decision.ActionAlert {
		if _, err := m.alertFile.Write(append(line, '\n')); err != nil {
			return err
		}
	}

	return nil
}

// openLogFile ensures the parent directory exists before opening the target file.
func openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
}
