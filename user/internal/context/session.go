package context

import (
	"time"

	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/process"
)

// SessionRecord is the in-memory aggregation unit that holds process state and recent history.
type SessionRecord struct {
	ID        uint32
	Processes map[uint32]*ProcessRecord

	RecentEvents []ObservedEvent
	Counts       EventCounts

	CreatedAt time.Time
	UpdatedAt time.Time
	ClosedAt  time.Time
	IsClosed  bool

	MaxLineageDepth       int
	UniqueConnectEndpoints []Endpoint
}

// ProcessRecord is the long-lived per-process cache from which feature extraction reads.
type ProcessRecord struct {
	PID  uint32
	PPID uint32
	UID  uint32

	Comm     string
	ExecPath string
	Args     []string
	LineageDepth int

	ExecCount    int
	OpenCount    int
	ConnectCount int

	Opens    []ObservedOpen
	Connects []ObservedConnect

	Lineage  []LineageNode
	Security *process.SecuritySnapshot

	FirstSeen time.Time
	LastSeen  time.Time
	ExitTime  time.Time
	ExitSeen  bool
}

// EventCounts stores generic session counters without embedding security semantics.
type EventCounts struct {
	Execs    int
	Opens    int
	Connects int
}

// Endpoint stores a normalized remote address observed during the session.
type Endpoint struct {
	Addr string
	Port uint16
}

// LineageNode stores the reduced ancestry view needed by execution context generation.
type LineageNode struct {
	PID  uint32
	PPID uint32
	Comm string
}

// ObservedEvent is the normalized event shape stored in recent session history.
type ObservedEvent struct {
	Type event.EventType
	PID  uint32

	Path string
	Addr string
	Port uint16

	Time time.Time
}

// ObservedOpen stores file access artifacts used by historical pattern matching.
type ObservedOpen struct {
	Path string
	Time time.Time
}

// ObservedConnect stores network artifacts used by historical pattern matching.
type ObservedConnect struct {
	Endpoint Endpoint
	Time     time.Time
}

// newSessionRecord initializes the in-memory container for one resolved session.
func newSessionRecord(id uint32, createdAt time.Time) *SessionRecord {
	return &SessionRecord{
		ID:              id,
		Processes:       make(map[uint32]*ProcessRecord),
		RecentEvents:    make([]ObservedEvent, 0, defaultRecentEventLimit),
		UniqueConnectEndpoints: make([]Endpoint, 0, 8),
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}
}

// getOrCreateProcess returns the per-process state bucket, creating it on first sighting.
func (s *SessionRecord) getOrCreateProcess(pid uint32, seenAt time.Time) *ProcessRecord {
	if p, ok := s.Processes[pid]; ok {
		return p
	}

	p := &ProcessRecord{
		PID:       pid,
		Opens:     make([]ObservedOpen, 0, 8),
		Connects:  make([]ObservedConnect, 0, 8),
		Lineage:   make([]LineageNode, 0, 4),
		FirstSeen: seenAt,
		LastSeen:  seenAt,
	}
	s.Processes[pid] = p
	return p
}

func (s *SessionRecord) allProcessesExited() bool {
	if len(s.Processes) == 0 {
		return false
	}

	for _, p := range s.Processes {
		if !p.ExitSeen {
			return false
		}
	}

	return true
}
