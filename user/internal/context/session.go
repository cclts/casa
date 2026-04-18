package context

import (
	"time"

	"github.com/cclts/care-go/user/internal/event"
)

type SessionState struct {
	ID        uint32
	RootPID   uint32
	Processes map[uint32]*ProcessState

	RecentEvents []ObservedEvent

	CreatedAt time.Time
	UpdatedAt time.Time
}

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

type LineageNode struct {
	PID  uint32
	PPID uint32
	Comm string
}

type ObservedEvent struct {
	Type event.EventType
	PID  uint32

	Path string
	Addr string
	Port uint32

	Time time.Time
}

type ObservedOpen struct {
	Path string
	Time time.Time
}

type ObservedConnect struct {
	Addr string
	Port uint32
	Time time.Time
}

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
