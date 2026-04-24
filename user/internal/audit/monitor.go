package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cclts/care-go/user/internal/context"
	"github.com/cclts/care-go/user/internal/decision"
	"github.com/cclts/care-go/user/internal/event"
)

// Monitor owns the append-only audit sinks used for routine logs and high-risk alerts.
type Monitor struct {
	mu        sync.Mutex
	logFile   *os.File
	alertFile *os.File
	queue     chan queuedRecord
	done      chan struct{}
	writerErr error
	closed    bool
}

type queuedRecord struct {
	record  Record
	isAlert bool
}

// Record is the JSONL payload written to disk for every non-ignored decision.
type Record struct {
	Timestamp string          `json:"timestamp"`
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
	Port uint16   `json:"port,omitempty"`
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

	m := &Monitor{
		logFile:   logFile,
		alertFile: alertFile,
		queue:     make(chan queuedRecord, 1024),
		done:      make(chan struct{}),
	}

	go m.runWriter()

	return m, nil
}

// runWriter serializes all disk writes through a single consumer goroutine.
func (m *Monitor) runWriter() {
	defer close(m.done)

	for item := range m.queue {
		if err := m.writeRecord(item); err != nil {
			m.mu.Lock()
			if m.writerErr == nil {
				m.writerErr = err
			}
			m.mu.Unlock()
		}
	}

	m.mu.Lock()
	if m.writerErr == nil {
		if err := syncFile(m.logFile); err != nil {
			m.writerErr = err
		}
	}
	if m.writerErr == nil {
		if err := syncFile(m.alertFile); err != nil {
			m.writerErr = err
		}
	}
	m.mu.Unlock()
}

// Close stops the producer-consumer pipeline, waits for queued records to flush,
// and then closes the underlying files.
func (m *Monitor) Close() error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.queue)
	}
	m.mu.Unlock()

	<-m.done

	m.mu.Lock()
	defer m.mu.Unlock()

	firstErr := m.writerErr
	if m.logFile != nil {
		if err := m.logFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.logFile = nil
	}
	if m.alertFile != nil {
		if err := m.alertFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.alertFile = nil
	}

	return firstErr
}

// Record enqueues the full decision snapshot and mirrors alerts to the dedicated
// alert sink inside the consumer goroutine.
func (m *Monitor) Record(e event.Event, ctx context.Context, result decision.Result) error {
	if result.Action == decision.ActionIgnore {
		return nil
	}

	record := Record{
		Timestamp: e.TimeHuman,
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

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writerErr != nil {
		return m.writerErr
	}
	if m.closed {
		return errors.New("audit monitor is closed")
	}

	m.queue <- queuedRecord{
		record:  record,
		isAlert: result.Action == decision.ActionAlert,
	}

	return nil
}

// writeRecord encodes one record and writes it to the configured sinks.
func (m *Monitor) writeRecord(item queuedRecord) error {
	line, err := json.Marshal(item.record)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if _, err := m.logFile.Write(line); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	if item.isAlert {
		if _, err := m.alertFile.Write(line); err != nil {
			return fmt.Errorf("write alert log: %w", err)
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

func syncFile(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Sync()
}
