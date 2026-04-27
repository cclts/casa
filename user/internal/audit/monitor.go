package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/rules"
)

const (
	defaultAuditLogPath   = "user/logs/audit.log"
	defaultAlertLogPath   = "user/logs/alert.log"
	defaultEventLogPath   = "user/logs/events.log"
	defaultSessionLogPath = "user/logs/sessions.log"
	sessionFlushInterval  = 30 * time.Second
	maxSessionEndpoints   = 16
)

// Monitor owns the append-only event and session log sinks.
type Monitor struct {
	mu          sync.Mutex
	eventFile   *os.File
	sessionFile *os.File
	sessions    map[uint32]*sessionAggregate
	done        chan struct{}
	stopFlush   chan struct{}
	writerErr   error
	closed      bool
}

// EventLogRecord is the JSONL payload written for every observed event.
type EventLogRecord struct {
	Timestamp string    `json:"timestamp"`
	SessionID uint32    `json:"session_id"`
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	UID       uint32    `json:"uid"`
	Type      string    `json:"type"`
	Comm      string    `json:"comm"`
	Path      *string   `json:"path,omitempty"`
	Args      *[]string `json:"args,omitempty"`
	Flags     *uint32   `json:"flags,omitempty"`
	Mode      *uint32   `json:"mode,omitempty"`
	Addr      *string   `json:"addr,omitempty"`
	Port      *uint16   `json:"port,omitempty"`
	Depth     int       `json:"depth"`
}

// SessionLogRecord is the JSONL payload written for session-level snapshots.
type SessionLogRecord struct {
	Timestamp string        `json:"timestamp"`
	SessionID uint32        `json:"session_id"`
	Reason    string        `json:"reason"`
	Session   SessionRecord `json:"session"`
}

// SessionRecord stores the monitor's current view of a session.
type SessionRecord struct {
	CreatedAt              string               `json:"created_at"`
	UpdatedAt              string               `json:"updated_at"`
	ClosedAt               string               `json:"closed_at,omitempty"`
	IsClosed               bool                 `json:"is_closed"`
	EventCounts            context.EventCounts  `json:"event_counts"`
	UniqueConnectEndpoints []context.Endpoint   `json:"unique_connect_endpoints"`
	MaxScore               int                  `json:"max_score"`
	AlertTriggered         bool                 `json:"alert_triggered"`
	FinalDecision          DecisionRecord       `json:"final_decision"`
	TriggeredRules         []rules.TriggeredRule `json:"triggered_rules"`
}

// EventRecord stores the normalized event fields that triggered evaluation.
type EventRecord struct {
	Type  string   `json:"type"`
	PID   uint32   `json:"pid"`
	PPID  uint32   `json:"ppid"`
	UID   uint32   `json:"uid"`
	Comm  string   `json:"comm"`
	Path  string   `json:"path,omitempty"`
	Args  []string `json:"args,omitempty"`
	Flags uint32   `json:"flags,omitempty"`
	Mode  uint32   `json:"mode,omitempty"`
	Addr  string   `json:"addr,omitempty"`
	Port  uint16   `json:"port,omitempty"`
}

// DecisionRecord stores the scoring output that explains why a record was logged.
type DecisionRecord struct {
	Action         decision.Action       `json:"action"`
	Score          int                   `json:"score"`
	LogThreshold   int                   `json:"log_threshold"`
	AlertThreshold int                   `json:"alert_threshold"`
	Triggered      []rules.TriggeredRule `json:"triggered_rules"`
}

type sessionAggregate struct {
	ID                     uint32
	CreatedAt              time.Time
	UpdatedAt              time.Time
	ClosedAt               time.Time
	IsClosed               bool
	EventCounts            context.EventCounts
	UniqueConnectEndpoints []context.Endpoint
	MaxScore               int
	AlertTriggered         bool
	FinalDecision          DecisionRecord
	TriggeredRules         []rules.TriggeredRule
	triggeredRuleIndex     map[string]struct{}
}

// NewMonitor opens append-only event and session log files.
func NewMonitor(logPath, alertPath string) (*Monitor, error) {
	eventPath := resolveLogPath(logPath, defaultAuditLogPath, defaultEventLogPath)
	sessionPath := resolveLogPath(alertPath, defaultAlertLogPath, defaultSessionLogPath)

	eventFile, err := openLogFile(eventPath)
	if err != nil {
		return nil, err
	}

	sessionFile, err := openLogFile(sessionPath)
	if err != nil {
		_ = eventFile.Close()
		return nil, err
	}

	m := &Monitor{
		eventFile:   eventFile,
		sessionFile: sessionFile,
		sessions:    make(map[uint32]*sessionAggregate),
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

	return firstErr
}

// Record writes every event to events.log and writes session snapshots only on
// root exit, first alert-threshold crossing, periodic flush, and shutdown.
func (m *Monitor) Record(e event.Event, ctx context.Context, result decision.Result) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.writerErr != nil {
		return m.writerErr
	}
	if m.closed {
		return errors.New("audit monitor is closed")
	}

	eventRecord := EventLogRecord{
		Timestamp: e.TimeHuman,
		SessionID: ctx.SessionID,
		PID:       e.PID,
		PPID:      e.PPID,
		UID:       e.UID,
		Type:      e.Type.String(),
		Comm:      e.Comm,
		Depth:     ctx.Execution.ChainDepth,
	}
	populateEventLogFields(&eventRecord, e)

	if err := m.writeJSONL(m.eventFile, eventRecord, "event log"); err != nil {
		m.writerErr = err
		return err
	}

	session := m.getOrCreateSessionLocked(ctx.SessionID, e.Time)
	updateSessionAggregate(session, e, result)

	if !session.AlertTriggered && result.CrossesAlertThreshold() {
		session.AlertTriggered = true
		if err := m.writeSessionRecordLocked(session, "alert_threshold_crossed", e.Time); err != nil {
			m.writerErr = err
			return err
		}
	}

	if e.Type == event.EventExit && e.PID == ctx.SessionID {
		session.IsClosed = true
		session.ClosedAt = e.Time
		if err := m.writeSessionRecordLocked(session, "session_root_exit", e.Time); err != nil {
			m.writerErr = err
			return err
		}
		delete(m.sessions, ctx.SessionID)
	}

	return nil
}

func (m *Monitor) getOrCreateSessionLocked(sessionID uint32, createdAt time.Time) *sessionAggregate {
	session, ok := m.sessions[sessionID]
	if ok {
		return session
	}

	session = &sessionAggregate{
		ID:                     sessionID,
		CreatedAt:              createdAt,
		UpdatedAt:              createdAt,
		UniqueConnectEndpoints: make([]context.Endpoint, 0, 8),
		TriggeredRules:         make([]rules.TriggeredRule, 0, 8),
		triggeredRuleIndex:     make(map[string]struct{}),
	}
	m.sessions[sessionID] = session
	return session
}

func updateSessionAggregate(session *sessionAggregate, e event.Event, result decision.Result) {
	session.UpdatedAt = e.Time
	if result.Score > session.MaxScore {
		session.MaxScore = result.Score
	}
	updateFinalDecision(session, result)
	mergeTriggeredRules(session, result.Triggered)

	switch e.Type {
	case event.EventExecve:
		session.EventCounts.Execs++
	case event.EventOpenat:
		session.EventCounts.Opens++
	case event.EventConnect:
		session.EventCounts.Connects++
		endpoint := context.Endpoint{Addr: e.Addr, Port: e.Port}
		session.UniqueConnectEndpoints = appendUniqueEndpoint(session.UniqueConnectEndpoints, endpoint)
	}
}

func (m *Monitor) flushSessionsLocked(reason string, clear bool) {
	now := time.Now()
	for id, session := range m.sessions {
		if err := m.writeSessionRecordLocked(session, reason, now); err != nil {
			m.writerErr = err
			return
		}
		if clear || session.IsClosed {
			delete(m.sessions, id)
		}
	}
}

func (m *Monitor) writeSessionRecordLocked(session *sessionAggregate, reason string, ts time.Time) error {
	record := SessionLogRecord{
		Timestamp: formatTimestamp(ts),
		SessionID: session.ID,
		Reason:    reason,
		Session:   snapshotSessionRecord(session),
	}

	return m.writeJSONL(m.sessionFile, record, "session log")
}

func snapshotSessionRecord(session *sessionAggregate) SessionRecord {
	record := SessionRecord{
		CreatedAt:              formatTimestamp(session.CreatedAt),
		UpdatedAt:              formatTimestamp(session.UpdatedAt),
		IsClosed:               session.IsClosed,
		EventCounts:            session.EventCounts,
		UniqueConnectEndpoints: append([]context.Endpoint(nil), session.UniqueConnectEndpoints...),
		MaxScore:               session.MaxScore,
		AlertTriggered:         session.AlertTriggered,
		FinalDecision:          session.FinalDecision,
		TriggeredRules:         append([]rules.TriggeredRule(nil), session.TriggeredRules...),
	}
	if !session.ClosedAt.IsZero() {
		record.ClosedAt = formatTimestamp(session.ClosedAt)
	}
	return record
}

func buildEventRecord(e event.Event) EventRecord {
	return EventRecord{
		Type:  e.Type.String(),
		PID:   e.PID,
		PPID:  e.PPID,
		UID:   e.UID,
		Comm:  e.Comm,
		Path:  e.Path,
		Args:  append([]string(nil), e.Args...),
		Flags: e.Flags,
		Mode:  e.Mode,
		Addr:  e.Addr,
		Port:  e.Port,
	}
}

func buildDecisionRecord(result decision.Result) DecisionRecord {
	return DecisionRecord{
		Action:         result.Action,
		Score:          result.Score,
		LogThreshold:   result.LogThreshold,
		AlertThreshold: result.AlertThreshold,
		Triggered:      append([]rules.TriggeredRule(nil), result.Triggered...),
	}
}

func updateFinalDecision(session *sessionAggregate, result decision.Result) {
	if actionPriority(result.Action) > actionPriority(session.FinalDecision.Action) ||
		(actionPriority(result.Action) == actionPriority(session.FinalDecision.Action) && result.Score >= session.FinalDecision.Score) {
		session.FinalDecision = buildDecisionRecord(result)
		return
	}

	if result.Score > session.FinalDecision.Score {
		session.FinalDecision.Score = result.Score
	}
}

func mergeTriggeredRules(session *sessionAggregate, triggered []rules.TriggeredRule) {
	for _, rule := range triggered {
		key := rule.Name
		if key == "" {
			key = rule.Expr
		}
		if _, ok := session.triggeredRuleIndex[key]; ok {
			continue
		}
		session.triggeredRuleIndex[key] = struct{}{}
		session.TriggeredRules = append(session.TriggeredRules, rule)
	}
}

func actionPriority(action decision.Action) int {
	switch action {
	case decision.ActionAlert:
		return 2
	case decision.ActionLog:
		return 1
	default:
		return 0
	}
}

func (m *Monitor) writeJSONL(file *os.File, payload any, label string) error {
	line, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if _, err := file.Write(line); err != nil {
		return fmt.Errorf("write %s: %w", label, err)
	}

	return nil
}

func resolveLogPath(path, legacyDefault, currentDefault string) string {
	if path == "" {
		return currentDefault
	}
	if path == legacyDefault {
		return currentDefault
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if base == filepath.Base(legacyDefault) {
		return filepath.Join(dir, filepath.Base(currentDefault))
	}
	return path
}

func populateEventLogFields(record *EventLogRecord, e event.Event) {
	switch e.Type {
	case event.EventExecve:
		record.Path = stringPtr(e.Path)
		args := append([]string(nil), e.Args...)
		record.Args = &args
	case event.EventOpenat:
		record.Path = stringPtr(e.Path)
		record.Flags = uint32Ptr(e.Flags)
		record.Mode = uint32Ptr(e.Mode)
	case event.EventConnect:
		record.Addr = stringPtr(e.Addr)
		record.Port = uint16Ptr(e.Port)
	case event.EventExit:
		// EXIT only keeps the common core fields.
	}
}

func appendUniqueEndpoint(items []context.Endpoint, endpoint context.Endpoint) []context.Endpoint {
	for _, item := range items {
		if item == endpoint {
			return items
		}
	}

	items = append(items, endpoint)
	if len(items) <= maxSessionEndpoints {
		return items
	}
	return items[len(items)-maxSessionEndpoints:]
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

func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Format(time.RFC3339Nano)
}

func stringPtr(v string) *string {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}
