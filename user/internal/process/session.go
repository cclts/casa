package process

import (
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cclts/casa/user/internal/event"
)

const sessionGracePeriod = 2 * time.Second

// SessionID identifies the current CLI-invocation-level session boundary.
type SessionID uint32

// Session groups a set of related processes under one resolved CLI invocation.
type Session struct {
	ID         SessionID
	SessionPID uint32
	Processes  map[uint32]struct{}

	CreatedAt  time.Time
	LastSeen   time.Time
	ClosedAt   time.Time
	GraceUntil time.Time
	IsClosing  bool
	IsClosed   bool
}

// SessionTracker maps observed pids back to the active OpenClaw CLI invocation.
type SessionTracker struct {
	mu sync.RWMutex

	sessions map[uint32]*Session

	pidToSession map[uint32]uint32
	rootToSession map[uint32]uint32

	tracker *Tracker
}

// NewSessionTracker creates the session resolver on top of the lineage tracker.
func NewSessionTracker(tracker *Tracker) *SessionTracker {
	return &SessionTracker{
		sessions:      make(map[uint32]*Session),
		pidToSession:  make(map[uint32]uint32),
		rootToSession: make(map[uint32]uint32),
		tracker:       tracker,
	}
}

// ObserveExecve updates session lifecycle on execve boundaries.
func (st *SessionTracker) ObserveExecve(e event.Event) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.expireSessionsLocked(e.Time)

	if isOpenClawCLIInvocation(st.tracker, e) {
		sess := &Session{
			ID:         SessionID(e.PID),
			SessionPID: e.PID,
			Processes:  map[uint32]struct{}{e.PID: {}},
			CreatedAt:  e.Time,
			LastSeen:   e.Time,
		}
		st.sessions[e.PID] = sess
		st.pidToSession[e.PID] = e.PID
		st.rootToSession[e.PPID] = e.PID
		log.Printf(
			"[SESSION] start id=%d cli_pid=%d root_pid=%d path=%s args=%v",
			sess.ID,
			sess.SessionPID,
			e.PPID,
			e.Path,
			e.Args,
		)
		return
	}

	if sessionPID, ok := st.pidToSession[e.PID]; ok {
		if sess, ok := st.sessions[sessionPID]; ok && sessionAcceptsEvents(sess, e.Time) {
			sess.LastSeen = e.Time
			sess.Processes[e.PID] = struct{}{}
			return
		}
	}

	if sessionPID, ok := st.pidToSession[e.PPID]; ok {
		if sess, ok := st.sessions[sessionPID]; ok && sessionAcceptsEvents(sess, e.Time) {
			sess.LastSeen = e.Time
			sess.Processes[e.PID] = struct{}{}
			st.pidToSession[e.PID] = sessionPID
			return
		}
	}

	if st.tracker.IsRoot(e.PPID) {
		if sessionPID, ok := st.rootToSession[e.PPID]; ok {
			if sess, ok := st.sessions[sessionPID]; ok && sessionAcceptsEvents(sess, e.Time) {
				sess.LastSeen = e.Time
				sess.Processes[e.PID] = struct{}{}
				st.pidToSession[e.PID] = sessionPID
			}
		}
	}
}

// Resolve returns the active or closing CLI session that owns the event.
func (st *SessionTracker) Resolve(e event.Event) (*Session, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.expireSessionsLocked(e.Time)

	if sess, ok := st.lookupSessionLocked(e.PID, e.Time); ok {
		sess.LastSeen = e.Time
		return sess, true
	}
	if sess, ok := st.lookupSessionLocked(e.PPID, e.Time); ok {
		sess.LastSeen = e.Time
		return sess, true
	}
	if st.tracker.IsRoot(e.PID) {
		if sess, ok := st.lookupRootSessionLocked(e.PID, e.Time); ok {
			sess.LastSeen = e.Time
			return sess, true
		}
	}
	if st.tracker.IsRoot(e.PPID) {
		if sess, ok := st.lookupRootSessionLocked(e.PPID, e.Time); ok {
			sess.LastSeen = e.Time
			return sess, true
		}
	}

	return nil, false
}

// ObserveExit updates closing state and session membership on process exit.
func (st *SessionTracker) ObserveExit(e event.Event) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.expireSessionsLocked(e.Time)

	sessionPID, ok := st.pidToSession[e.PID]
	if ok {
		delete(st.pidToSession, e.PID)
	}

	sess, ok := st.sessions[sessionPID]
	if !ok {
		if st.tracker.IsRoot(e.PID) {
			if sessionPID, ok := st.rootToSession[e.PID]; ok {
				if sess, ok := st.sessions[sessionPID]; ok {
					markSessionClosing(sess, e.Time)
				}
			}
		}
		return
	}

	delete(sess.Processes, e.PID)
	if e.PID == sess.SessionPID {
		markSessionClosing(sess, e.Time)
	}
	if len(sess.Processes) == 0 && sess.IsClosing {
		sess.IsClosed = true
		sess.ClosedAt = e.Time
		log.Printf(
			"[SESSION] end id=%d cli_pid=%d closed_at=%s",
			sess.ID,
			sess.SessionPID,
			sess.ClosedAt.Format(time.RFC3339Nano),
		)
	}
}

func (st *SessionTracker) lookupSessionLocked(pid uint32, now time.Time) (*Session, bool) {
	sessionPID, ok := st.pidToSession[pid]
	if !ok {
		return nil, false
	}
	sess, ok := st.sessions[sessionPID]
	if !ok || !sessionAcceptsEvents(sess, now) {
		return nil, false
	}
	return sess, true
}

func (st *SessionTracker) lookupRootSessionLocked(rootPID uint32, now time.Time) (*Session, bool) {
	sessionPID, ok := st.rootToSession[rootPID]
	if !ok {
		return nil, false
	}
	sess, ok := st.sessions[sessionPID]
	if !ok || !sessionAcceptsEvents(sess, now) {
		return nil, false
	}
	return sess, true
}

func (st *SessionTracker) expireSessionsLocked(now time.Time) {
	for rootPID, sessionPID := range st.rootToSession {
		sess, ok := st.sessions[sessionPID]
		if !ok || sessionExpired(sess, now) {
			delete(st.rootToSession, rootPID)
		}
	}

	for sessionPID, sess := range st.sessions {
		if !sessionExpired(sess, now) {
			continue
		}
		sess.IsClosed = true
		if sess.ClosedAt.IsZero() {
			sess.ClosedAt = sess.GraceUntil
			if sess.ClosedAt.IsZero() {
				sess.ClosedAt = now
			}
		}
		log.Printf(
			"[SESSION] end id=%d cli_pid=%d closed_at=%s",
			sess.ID,
			sess.SessionPID,
			sess.ClosedAt.Format(time.RFC3339Nano),
		)
		delete(st.sessions, sessionPID)
	}
}

func markSessionClosing(sess *Session, closedAt time.Time) {
	if sess == nil || sess.IsClosed {
		return
	}
	sess.IsClosing = true
	sess.GraceUntil = closedAt.Add(sessionGracePeriod)
}

func sessionAcceptsEvents(sess *Session, now time.Time) bool {
	if sess == nil || sess.IsClosed {
		return false
	}
	if !sess.IsClosing {
		return true
	}
	return now.Before(sess.GraceUntil) || now.Equal(sess.GraceUntil)
}

func sessionExpired(sess *Session, now time.Time) bool {
	if sess == nil {
		return true
	}
	if sess.IsClosed {
		return true
	}
	if !sess.IsClosing {
		return false
	}
	return now.After(sess.GraceUntil)
}

func isOpenClawCLIInvocation(tracker *Tracker, e event.Event) bool {
	if e.Type != event.EventExecve {
		return false
	}
	if !tracker.IsRoot(e.PPID) {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(e.Comm)), "openclaw") {
		return false
	}

	base := strings.ToLower(filepath.Base(strings.TrimSpace(e.Path)))
	switch base {
	case "sh", "bash", "zsh":
		return true
	default:
		return false
	}
}
