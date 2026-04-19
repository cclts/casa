package context

import (
	"time"

	"github.com/cclts/care-go/user/internal/event"
)

// SessionState is the in-memory aggregation unit that holds process state and recent history.
type SessionState struct {
	ID        uint32
	RootPID   uint32
	Processes map[uint32]*ProcessState

	RecentEvents []ObservedEvent

	CreatedAt time.Time
	UpdatedAt time.Time
}

// ProcessState is the long-lived per-process cache from which feature extraction reads.
type ProcessState struct {
	PID  uint32
	PPID uint32
	UID  uint32

	Comm     string
	ExecPath string
	Args     []string
	Depth    int

	ExecCount    int
	OpenCount    int
	ConnectCount int

	Opens    []ObservedOpen
	Connects []ObservedConnect

	Lineage []LineageNode

	FirstSeen time.Time
	LastSeen  time.Time
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
	Port uint32

	Time time.Time
}

// ObservedOpen stores file access artifacts used by historical pattern matching.
type ObservedOpen struct {
	Path string
	Time time.Time
}

// ObservedConnect stores network artifacts used by historical pattern matching.
type ObservedConnect struct {
	Addr string
	Port uint32
	Time time.Time
}

// newSessionState initializes the in-memory container for one resolved session.
func newSessionState(id uint32) *SessionState {
	now := time.Now()

	return &SessionState{
		ID:          id,
		RootPID:     id,
		Processes:   make(map[uint32]*ProcessState),
		RecentEvents: make([]ObservedEvent, 0, defaultRecentEventLimit),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// ensureProcess returns the per-process state bucket, creating it on first sighting.
func (s *SessionState) ensureProcess(pid uint32) *ProcessState {
	if p, ok := s.Processes[pid]; ok {
		return p
	}

	now := time.Now()
	p := &ProcessState{
		PID:       pid,
		Opens:     make([]ObservedOpen, 0, 8),
		Connects:  make([]ObservedConnect, 0, 8),
		Lineage:   make([]LineageNode, 0, 4),
		FirstSeen: now,
		LastSeen:  now,
	}
	s.Processes[pid] = p
	return p
}
