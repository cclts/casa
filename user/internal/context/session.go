package context

import (
	"time"

	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/process"
)

// SessionState is the in-memory aggregation unit that holds process state and recent history.
type SessionState struct {
	ID        uint32
	Processes map[uint32]*ProcessState

	RecentEvents []ObservedEvent
	Counts       EventCounts

	CreatedAt time.Time
	UpdatedAt time.Time
	ClosedAt  time.Time
	IsClosed  bool

	MaxLineageDepth       int
	UniqueConnectEndpoints []Endpoint
}

// ProcessState is the long-lived per-process cache from which feature extraction reads.
type ProcessState struct {
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
	Flags uint32
	Mode  uint32
	Addr string
	Port uint16

	Time time.Time
}

// ObservedOpen stores file access artifacts used by historical pattern matching.
type ObservedOpen struct {
	Path  string
	Flags uint32
	Mode  uint32
	Time  time.Time
}

// ObservedConnect stores network artifacts used by historical pattern matching.
type ObservedConnect struct {
	Endpoint Endpoint
	Time     time.Time
}

// newSessionState initializes the in-memory container for one resolved session.
func newSessionState(id uint32, createdAt time.Time) *SessionState {
	return &SessionState{
		ID:              id,
		Processes:       make(map[uint32]*ProcessState),
		RecentEvents:    make([]ObservedEvent, 0, defaultRecentEventLimit),
		UniqueConnectEndpoints: make([]Endpoint, 0, 8),
		CreatedAt:       createdAt,
		UpdatedAt:       createdAt,
	}
}

// getOrCreateProcess returns the per-process state bucket, creating it on first sighting.
func (s *SessionState) getOrCreateProcess(pid uint32, seenAt time.Time) *ProcessState {
	if p, ok := s.Processes[pid]; ok {
		return p
	}

	p := &ProcessState{
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

func (s *SessionState) allProcessesExited() bool {
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
