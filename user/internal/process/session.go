package process

import (
	"strings"
	"sync"
	"time"
)

type SessionID uint32

type Session struct {
	ID         SessionID
	SessionPID uint32
	Processes  map[uint32]struct{}

	CreatedAt time.Time
	LastSeen  time.Time
}

type SessionTracker struct {
	mu sync.RWMutex

	sessions map[uint32]*Session

	pidToSession map[uint32]uint32

	tracker *Tracker
}

func NewSessionTracker(tracker *Tracker) *SessionTracker {
	return &SessionTracker{
		sessions:     make(map[uint32]*Session),
		pidToSession: make(map[uint32]uint32),
		tracker:      tracker,
	}
}

func (st *SessionTracker) ResolveSession(pid uint32) (*Session, Lineage, bool) {
	lineage := BuildLineage(int(pid), st.tracker)

	var sessionPID uint32
	found := false

	// resolve session root
	for _, n := range lineage.Nodes {
		if st.tracker.IsRoot(uint32(n.PPID)) &&
			strings.HasPrefix(n.Comm, "openclaw") {
			sessionPID = uint32(n.PID)
			found = true
			break
		}
	}

	if !found {
		return nil, lineage, false
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	// get or create session
	sess, ok := st.sessions[sessionPID]
	if !ok {
		sess = &Session{
			ID:         SessionID(sessionPID),
			SessionPID: sessionPID,
			Processes:  make(map[uint32]struct{}),
			CreatedAt:  time.Now(),
		}
		st.sessions[sessionPID] = sess
	}

	now := time.Now()
	sess.LastSeen = now

	// add nodes to session
	for _, n := range lineage.Nodes {
		pid := uint32(n.PID)
		sess.Processes[pid] = struct{}{}
		st.pidToSession[pid] = sessionPID
	}

	return sess, lineage, true
}
