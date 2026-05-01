package audit

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
)

const sessionFlushInterval = 30 * time.Second

// Monitor owns the append-only events, sessions, audit, and alert log sinks.
type Monitor struct {
	mu          sync.Mutex
	eventFile   *os.File
	sessionFile *os.File
	auditFile   *os.File
	alertFile   *os.File
	sessions    map[uint32]*sessionAggregate
	rawSessions map[uint32]context.SessionSnapshot
	pending     map[eventKey]event.Event
	done        chan struct{}
	stopFlush   chan struct{}
	writerErr   error
	closed      bool
}

type eventKey struct {
	Type    event.EventType
	PID     uint32
	TID     uint32
	KTimeNS uint64
}

// NewMonitor opens append-only events.log, sessions.log, audit.log, and alert.log files.
func NewMonitor(eventPath, sessionPath, logPath, alertPath string) (*Monitor, error) {
	if eventPath == "" {
		eventPath = defaultEventLogPath
	}
	if sessionPath == "" {
		sessionPath = defaultSessionLogPath
	}
	if logPath == "" {
		logPath = defaultAuditLogPath
	}
	if alertPath == "" {
		alertPath = defaultAlertLogPath
	}

	eventFile, err := openLogFile(eventPath)
	if err != nil {
		return nil, err
	}

	sessionFile, err := openLogFile(sessionPath)
	if err != nil {
		_ = eventFile.Close()
		return nil, err
	}

	auditFile, err := openLogFile(logPath)
	if err != nil {
		_ = eventFile.Close()
		_ = sessionFile.Close()
		return nil, err
	}

	alertFile, err := openLogFile(alertPath)
	if err != nil {
		_ = eventFile.Close()
		_ = sessionFile.Close()
		_ = auditFile.Close()
		return nil, err
	}

	m := &Monitor{
		eventFile:   eventFile,
		sessionFile: sessionFile,
		auditFile:   auditFile,
		alertFile:   alertFile,
		sessions:    make(map[uint32]*sessionAggregate),
		rawSessions: make(map[uint32]context.SessionSnapshot),
		pending:     make(map[eventKey]event.Event),
		done:        make(chan struct{}),
		stopFlush:   make(chan struct{}),
	}

	go m.runPeriodicFlush()

	return m, nil
}

func (m *Monitor) runPeriodicFlush() {
	defer close(m.done)

	ticker := time.NewTicker(sessionFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			if m.writerErr == nil && !m.closed {
				m.flushSessionsLocked("periodic_flush", false)
			}
			m.mu.Unlock()
		case <-m.stopFlush:
			return
		}
	}
}

// Close flushes remaining session state, syncs files, and closes the sinks.
func (m *Monitor) Close() error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.stopFlush)
	}
	m.mu.Unlock()

	<-m.done

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writerErr == nil {
		m.flushSessionsLocked("shutdown", true)
	}

	firstErr := m.writerErr
	if firstErr == nil {
		if err := syncFile(m.eventFile); err != nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		if err := syncFile(m.sessionFile); err != nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		if err := syncFile(m.auditFile); err != nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		if err := syncFile(m.alertFile); err != nil {
			firstErr = err
		}
	}
	if m.eventFile != nil {
		if err := m.eventFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.eventFile = nil
	}
	if m.sessionFile != nil {
		if err := m.sessionFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.sessionFile = nil
	}
	if m.auditFile != nil {
		if err := m.auditFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.auditFile = nil
	}
	if m.alertFile != nil {
		if err := m.alertFile.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.alertFile = nil
	}

	return firstErr
}

// RecordEvent registers an observed event so it can be written to events.log
// once the pipeline finishes deriving session/context metadata for it.
func (m *Monitor) RecordEvent(e event.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writerErr != nil {
		return m.writerErr
	}
	if m.closed {
		return errors.New("audit monitor is closed")
	}

	m.pending[eventKeyFromEvent(e)] = e
	return nil
}

// DiscardEvent drops a staged event when no full Record call will follow.
func (m *Monitor) DiscardEvent(e event.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pending, eventKeyFromEvent(e))
}

// Record writes thresholded audit logs and session snapshots. It also flushes
// the corresponding events.log record now that session/context metadata exists.
func (m *Monitor) Record(e event.Event, raw context.SessionSnapshot, depth int, result decision.Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writerErr != nil {
		return m.writerErr
	}
	if m.closed {
		return errors.New("audit monitor is closed")
	}

	if err := m.writePendingEventLocked(e, raw.ID, depth); err != nil {
		m.writerErr = err
		return err
	}

	session := m.getOrCreateSessionLocked(raw.ID, e.Time)
	m.rawSessions[raw.ID] = raw

	if result.Score >= result.LogThreshold {
		if err := m.writeFullRecordLocked(m.auditFile, "audit log", session, e, result); err != nil {
			m.writerErr = err
			return err
		}
	}

	if result.CrossesAlertThreshold() {
		if err := m.writeFullRecordLocked(m.alertFile, "alert log", session, e, result); err != nil {
			m.writerErr = err
			return err
		}
	}

	if !session.AlertTriggered && result.CrossesAlertThreshold() {
		session.AlertTriggered = true
		if err := m.writeSessionRecordLocked(raw, session, "alert_threshold_crossed", e.Time); err != nil {
			m.writerErr = err
			return err
		}
	}

	if e.Type == event.EventExit && !raw.ClosedAt.IsZero() && raw.ClosedAt.Equal(e.Time) {
		if err := m.writeSessionRecordLocked(raw, session, "session_root_exit", e.Time); err != nil {
			m.writerErr = err
			return err
		}
		delete(m.sessions, raw.ID)
		delete(m.rawSessions, raw.ID)
	}

	return nil
}

func (m *Monitor) writePendingEventLocked(e event.Event, sessionID uint32, depth int) error {
	key := eventKeyFromEvent(e)
	raw, ok := m.pending[key]
	if ok {
		delete(m.pending, key)
	} else {
		raw = e
	}

	eventRecord := buildEventLogRecord(raw, sessionID, depth)
	return writeJSONL(m.eventFile, eventRecord, "event log")
}

func (m *Monitor) flushSessionsLocked(reason string, clear bool) {
	now := time.Now()
	for id, session := range m.sessions {
		raw, ok := m.rawSessions[id]
		if !ok {
			continue
		}
		if err := m.writeSessionRecordLocked(raw, session, reason, now); err != nil {
			m.writerErr = err
			return
		}
		if clear || !raw.ClosedAt.IsZero() {
			delete(m.sessions, id)
			delete(m.rawSessions, id)
		}
	}
}

func (m *Monitor) writeSessionRecordLocked(raw context.SessionSnapshot, session *sessionAggregate, reason string, ts time.Time) error {
	record := SessionLogRecord{
		Timestamp: formatTimestamp(ts),
		SessionID: raw.ID,
		Reason:    reason,
		Session:   snapshotSessionRecord(raw),
	}

	return writeJSONL(m.sessionFile, record, "session log")
}

func (m *Monitor) writeFullRecordLocked(file *os.File, label string, session *sessionAggregate, e event.Event, result decision.Result) error {
	record := FullLogRecord{
		Timestamp: e.TimeHuman,
		SessionID: session.ID,
		Event:     buildEventRecord(e),
		Decision:  buildDecisionRecord(result),
	}

	return writeJSONL(file, record, label)
}

func (m *Monitor) getOrCreateSessionLocked(sessionID uint32, createdAt time.Time) *sessionAggregate {
	session, ok := m.sessions[sessionID]
	if ok {
		return session
	}

	session = &sessionAggregate{
		ID: sessionID,
	}
	m.sessions[sessionID] = session
	return session
}

func eventKeyFromEvent(e event.Event) eventKey {
	return eventKey{
		Type:    e.Type,
		PID:     e.PID,
		TID:     e.TID,
		KTimeNS: e.KTimeNS,
	}
}
