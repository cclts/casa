package context

import (
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

// SessionState is the in-memory aggregation unit that holds process state and recent history.
type SessionState struct {
	ID        uint32
	Processes map[uint32]*ProcessState

	RecentEvents []ObservedEvent

	CreatedAt time.Time
	UpdatedAt time.Time
	ClosedAt  time.Time
}

// SessionSnapshot is the exported session-level raw state view.
type SessionSnapshot struct {
	ID           uint32
	Processes    map[uint32]*ProcessState
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ClosedAt     time.Time
	RecentEvents []ObservedEvent
}

// ProcessState is the long-lived per-process cache from which feature extraction reads.
type ProcessState struct {
	PID  uint32
	PPID uint32
	UID  uint32

	Comm         string
	ExecPath     string
	Args         []string
	LineageDepth int

	Opens    []ObservedOpen
	Connects []ObservedConnect

	Lineage  []LineageNode
	Security *process.SecuritySnapshot

	FirstSeen time.Time
	LastSeen  time.Time
	ExitTime  time.Time
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

	Path  string
	Flags uint32
	Mode  uint32
	Addr  string
	Port  uint16

	Time time.Time
}

// ObservedOpen stores file access artifacts used by historical pattern matching.
type ObservedOpen struct {
	Path  string
	Flags uint32
	Mode  uint32
	Time  time.Time
}

// Endpoint stores one normalized remote address observed from a process.
type Endpoint struct {
	Addr string
	Port uint16
}

// ObservedConnect stores network artifacts used by historical pattern matching.
type ObservedConnect struct {
	Endpoint Endpoint
	Time     time.Time
}

// newSessionState initializes the in-memory container for one resolved session.
func newSessionState(id uint32, createdAt time.Time) *SessionState {
	return &SessionState{
		ID:           id,
		Processes:    make(map[uint32]*ProcessState),
		RecentEvents: make([]ObservedEvent, 0, CurrentHeuristics().RecentEventLimit),
		CreatedAt:    createdAt,
		UpdatedAt:    createdAt,
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

func (s *SessionState) snapshot() SessionSnapshot {
	processes := make(map[uint32]*ProcessState, len(s.Processes))
	for pid, procState := range s.Processes {
		if procState == nil {
			continue
		}
		processes[pid] = cloneProcessState(procState)
	}
	recentEvents := make([]ObservedEvent, len(s.RecentEvents))
	copy(recentEvents, s.RecentEvents)

	return SessionSnapshot{
		ID:           s.ID,
		Processes:    processes,
		CreatedAt:    s.CreatedAt,
		UpdatedAt:    s.UpdatedAt,
		ClosedAt:     s.ClosedAt,
		RecentEvents: recentEvents,
	}
}

func cloneProcessState(procState *ProcessState) *ProcessState {
	if procState == nil {
		return nil
	}

	cloned := *procState
	cloned.Args = append([]string(nil), procState.Args...)
	cloned.Opens = append([]ObservedOpen(nil), procState.Opens...)
	cloned.Connects = append([]ObservedConnect(nil), procState.Connects...)
	cloned.Lineage = append([]LineageNode(nil), procState.Lineage...)
	if procState.Security != nil {
		security := *procState.Security
		cloned.Security = &security
	}
	return &cloned
}
