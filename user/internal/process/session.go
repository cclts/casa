package process

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	rootAttributionWindow       = 1 * time.Second
	rootAttributionRecentSkew   = 250 * time.Millisecond
	rootAttributionHistoryLimit = 16
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
	ClosedAt  time.Time
	IsClosed  bool
}

// SessionTracker maps observed pids back to the worker process that owns the session.
type SessionTracker struct {
	mu sync.RWMutex

	sessions map[uint32]*Session

	pidToSession map[uint32]uint32
	rootHints    map[uint32][]rootAttributionHint

	tracker *Tracker
}

type rootAttributionHint struct {
	SessionPID uint32
	SourcePID  uint32
	SeenAt     time.Time
}

// NewSessionTracker creates the session resolver on top of the lineage tracker.
func NewSessionTracker(tracker *Tracker) *SessionTracker {
	return &SessionTracker{
		sessions:     make(map[uint32]*Session),
		pidToSession: make(map[uint32]uint32),
		rootHints:    make(map[uint32][]rootAttributionHint),
		tracker:      tracker,
	}
}

// ResolveSession walks lineage and decides whether the pid belongs to a tracked OpenClaw session.
func (st *SessionTracker) ResolveSession(pid uint32, eventTime time.Time, maxDepth int) (*Session, Lineage, bool) {
	lineage := BuildLineage(int(pid), st.tracker, maxDepth)

	var sessionPID uint32
	var rootPID uint32
	found := false

	// Today a session is anchored at the OpenClaw worker node beneath a tracked root.
	// This keeps aggregation stable across child processes and execve boundaries.
	for _, n := range lineage.Nodes {
		if st.tracker.IsRoot(uint32(n.PID)) {
			rootPID = uint32(n.PID)
		}
		if st.tracker.IsRoot(uint32(n.PPID)) &&
			strings.HasPrefix(n.Comm, "openclaw") {
			sessionPID = uint32(n.PID)
			rootPID = uint32(n.PPID)
			found = true
			break
		}
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	if !found && st.tracker.IsRoot(pid) {
		sess, ok := st.resolveRootEventLocked(pid, eventTime)
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

	if rootPID != 0 && pid != rootPID {
		st.recordRootHintLocked(rootPID, sessionPID, pid, eventTime)
	}

	return sess, lineage, true
}

func (st *SessionTracker) resolveRootEventLocked(rootPID uint32, now time.Time) (*Session, bool) {
	hints := st.rootHints[rootPID]
	if len(hints) == 0 {
		return nil, false
	}

	filtered := hints[:0]
	candidates := make(map[uint32]time.Time)
	for _, hint := range hints {
		if now.Sub(hint.SeenAt) > rootAttributionWindow {
			continue
		}
		filtered = append(filtered, hint)
		if seenAt, ok := candidates[hint.SessionPID]; !ok || hint.SeenAt.After(seenAt) {
			candidates[hint.SessionPID] = hint.SeenAt
		}
	}
	st.rootHints[rootPID] = filtered

	if len(candidates) == 0 {
		return nil, false
	}

	if len(candidates) == 1 {
		for sessionPID := range candidates {
			sess, ok := st.sessions[sessionPID]
			if !ok || sess == nil || sess.IsClosed {
				return nil, false
			}
			return sess, true
		}
	}

	var bestSessionPID uint32
	var bestSeenAt time.Time
	var secondBest time.Time
	for sessionPID, seenAt := range candidates {
		if seenAt.After(bestSeenAt) {
			secondBest = bestSeenAt
			bestSeenAt = seenAt
			bestSessionPID = sessionPID
			continue
		}
		if seenAt.After(secondBest) {
			secondBest = seenAt
		}
	}

	if bestSessionPID == 0 {
		return nil, false
	}
	if !secondBest.IsZero() && bestSeenAt.Sub(secondBest) < rootAttributionRecentSkew {
		return nil, false
	}

	sess, ok := st.sessions[bestSessionPID]
	if !ok || sess == nil || sess.IsClosed {
		return nil, false
	}
	return sess, true
}

func (st *SessionTracker) recordRootHintLocked(rootPID uint32, sessionPID uint32, sourcePID uint32, seenAt time.Time) {
	hints := append(st.rootHints[rootPID], rootAttributionHint{
		SessionPID: sessionPID,
		SourcePID:  sourcePID,
		SeenAt:     seenAt,
	})
	if len(hints) > rootAttributionHistoryLimit {
		hints = hints[len(hints)-rootAttributionHistoryLimit:]
	}
	st.rootHints[rootPID] = hints
}

// DebugRootHints returns a human-readable snapshot of the current attribution
// hints for one tracked root. This is intended for targeted troubleshooting.
func (st *SessionTracker) DebugRootHints(rootPID uint32, now time.Time) string {
	st.mu.RLock()
	defer st.mu.RUnlock()

	hints := st.rootHints[rootPID]
	if len(hints) == 0 {
		return "none"
	}

	parts := make([]string, 0, len(hints))
	for _, hint := range hints {
		age := now.Sub(hint.SeenAt)
		parts = append(parts, fmt.Sprintf("session=%d source=%d age=%s", hint.SessionPID, hint.SourcePID, age.Round(time.Millisecond)))
	}
	return strings.Join(parts, "; ")
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
