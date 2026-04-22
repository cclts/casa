package process

import (
	"strings"
	"sync"
	"time"
)

// SessionID identifies the worker-level session boundary currently used by the pipeline.
type SessionID uint32

// Session groups a set of related processes under one resolved worker root.
type Session struct {
	ID         SessionID
	SessionPID uint32
	Processes  map[uint32]struct{}

	CreatedAt time.Time
	LastSeen  time.Time
}

// SessionTracker maps observed pids back to the worker process that owns the session.
type SessionTracker struct {
	mu sync.RWMutex

	sessions map[uint32]*Session

	pidToSession map[uint32]uint32

	tracker *Tracker
}

// NewSessionTracker creates the session resolver on top of the lineage tracker.
func NewSessionTracker(tracker *Tracker) *SessionTracker {
	return &SessionTracker{
		sessions:     make(map[uint32]*Session),
		pidToSession: make(map[uint32]uint32),
		tracker:      tracker,
	}
}

// ResolveSession walks lineage and decides whether the pid belongs to a tracked OpenClaw session.
func (st *SessionTracker) ResolveSession(pid uint32, eventTime time.Time, maxDepth int) (*Session, Lineage, bool) {
	lineage := BuildLineage(int(pid), st.tracker, maxDepth)

	var sessionPID uint32
	found := false

	// Today a session is anchored at the OpenClaw worker node beneath a tracked root.
	// This keeps aggregation stable across child processes and execve boundaries.
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
			CreatedAt:  eventTime,
		}
		st.sessions[sessionPID] = sess
	}

	sess.LastSeen = eventTime

	// add nodes to session
	for _, n := range lineage.Nodes {
		pid := uint32(n.PID)
		sess.Processes[pid] = struct{}{}
		st.pidToSession[pid] = sessionPID
	}

	return sess, lineage, true
}
