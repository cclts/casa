package process

import (
	"strings"
	"sync"
	"time"
)

const rootEventSessionFallbackWindow = 10 * time.Second

// SessionID identifies the worker-level session boundary currently used by the pipeline.
type SessionID uint32

// Session groups a set of related processes under one resolved worker root.
type Session struct {
	ID         SessionID
	SessionPID uint32
	Processes  map[uint32]struct{}

	CreatedAt time.Time
	LastSeen  time.Time
	ClosedAt  time.Time
	IsClosed  bool
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

	if !found && st.tracker.IsRoot(pid) {
		sess, ok := st.findRecentActiveSessionLocked(eventTime)
		if !ok {
			return nil, lineage, false
		}
		sess.LastSeen = eventTime
		return sess, lineage, true
	}

	if !found {
		return nil, lineage, false
	}

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
	sess.Processes[pid] = struct{}{}
	st.pidToSession[pid] = sessionPID

	// add nodes to session
	for _, n := range lineage.Nodes {
		pid := uint32(n.PID)
		sess.Processes[pid] = struct{}{}
		st.pidToSession[pid] = sessionPID
	}

	return sess, lineage, true
}

func (st *SessionTracker) findRecentActiveSessionLocked(now time.Time) (*Session, bool) {
	var match *Session

	for _, sess := range st.sessions {
		if sess == nil || sess.IsClosed {
			continue
		}
		if now.Sub(sess.LastSeen) > rootEventSessionFallbackWindow {
			continue
		}
		if match != nil {
			return nil, false
		}
		match = sess
	}

	if match == nil {
		return nil, false
	}
	return match, true
}

// HandleExit marks a tracked process as exited and closes the session when its anchor exits.
func (st *SessionTracker) HandleExit(pid uint32, eventTime time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()

	sessionPID, ok := st.pidToSession[pid]
	if !ok {
		return
	}

	delete(st.pidToSession, pid)

	sess, ok := st.sessions[sessionPID]
	if !ok {
		return
	}

	delete(sess.Processes, pid)
	if pid == sessionPID || len(sess.Processes) == 0 {
		sess.IsClosed = true
		sess.ClosedAt = eventTime
	}
}
