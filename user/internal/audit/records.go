package audit

import (
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/rules"
)

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
	CreatedAt              string                `json:"created_at"`
	UpdatedAt              string                `json:"updated_at"`
	ClosedAt               string                `json:"closed_at,omitempty"`
	IsClosed               bool                  `json:"is_closed"`
	EventCounts            context.EventCounts   `json:"event_counts"`
	UniqueConnectEndpoints []context.Endpoint    `json:"unique_connect_endpoints"`
	MaxScore               int                   `json:"max_score"`
	AlertTriggered         bool                  `json:"alert_triggered"`
	FinalDecision          DecisionRecord        `json:"final_decision"`
	TriggeredRules         []rules.TriggeredRule `json:"triggered_rules"`
}

// EventRecord stores the normalized event fields that triggered evaluation.
type EventRecord struct {
	Type  string    `json:"type"`
	PID   uint32    `json:"pid"`
	PPID  uint32    `json:"ppid"`
	UID   uint32    `json:"uid"`
	Comm  string    `json:"comm"`
	Path  *string   `json:"path,omitempty"`
	Args  *[]string `json:"args,omitempty"`
	Flags *uint32   `json:"flags,omitempty"`
	Mode  *uint32   `json:"mode,omitempty"`
	Addr  *string   `json:"addr,omitempty"`
	Port  *uint16   `json:"port,omitempty"`
}

// FullLogRecord stores the complete thresholded log entry written to audit.log
// and alert.log.
type FullLogRecord struct {
	Timestamp string         `json:"timestamp"`
	SessionID uint32         `json:"session_id"`
	Event     EventRecord    `json:"event"`
	Session   SessionRecord  `json:"session"`
	Decision  DecisionRecord `json:"decision"`
}

// DecisionRecord stores the scoring output that explains why a record was logged.
type DecisionRecord struct {
	Action         decision.Action       `json:"action"`
	Score          int                   `json:"score"`
	LogThreshold   int                   `json:"log_threshold"`
	AlertThreshold int                   `json:"alert_threshold"`
	TriggeredRules []rules.TriggeredRule `json:"triggered_rules"`
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
