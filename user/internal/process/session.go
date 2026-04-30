package process

import (
	"context"
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

	CreatedAt  time.Time
	ClosingAt  time.Time
	GraceUntil time.Time
}

// SessionTracker maps observed pids back to the active OpenClaw CLI invocation.
type SessionTracker struct {
	mu sync.RWMutex

	sessions map[SessionID]*Session

	activeSessionID SessionID
	nextSessionID   SessionID
}

// NewSessionTracker creates the session resolver for CLI invocation windows.
func NewSessionTracker() *SessionTracker {
	return &SessionTracker{
		sessions:      make(map[SessionID]*Session),
		nextSessionID: 1,
	}
}

// StartJanitor periodically expires closing sessions after their grace period elapses.
func (st *SessionTracker) StartJanitor(ctx context.Context, interval time.Duration, onExpired func(SessionID, time.Time)) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				for _, expired := range st.Expire(now) {
					if onExpired != nil {
						onExpired(expired.ID, expired.ClosedAt)
					}
				}
			}
		}
	}()
}

type ExpiredSession struct {
	ID       SessionID
	ClosedAt time.Time
}

// Expire closes sessions whose grace period elapsed and returns the sessions
// that transitioned to closed during this sweep.
func (st *SessionTracker) Expire(now time.Time) []ExpiredSession {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.expireSessionsLocked(now)
}

// ObserveExecve updates session lifecycle on execve boundaries.
func (st *SessionTracker) ObserveExecve(e event.Event) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.expireSessionsLocked(e.Time)

	if isOpenClawCLIInvocation(e) {
		id := st.nextSessionID
		st.nextSessionID++

		sess := &Session{
			ID:         id,
			SessionPID: e.PID,
			CreatedAt:  e.Time,
		}
		st.sessions[id] = sess
		st.activeSessionID = id
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
}

// ObserveExit updates closing state on process exit. Only the CLI invocation
// pid itself defines the session boundary; other process exits do not affect
// the session window directly.
func (st *SessionTracker) ObserveExit(e event.Event) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.expireSessionsLocked(e.Time)

	sess, ok := st.activeSessionLocked(e.Time)
	if !ok {
		return
	}
	if e.PID == sess.SessionPID {
		markSessionClosing(sess, e.Time)
	}
}

// ActiveSession returns the single active/closing session window, if any.
func (st *SessionTracker) ActiveSession(now time.Time) (*Session, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	st.expireSessionsLocked(now)
	return st.activeSessionLocked(now)
}

// activeSessionLocked returns the single active/closing session used by the
// evaluation-first model after verifying it still accepts events at `now`.
func (st *SessionTracker) activeSessionLocked(now time.Time) (*Session, bool) {
	if st.activeSessionID == 0 {
		return nil, false
	}
	sess, ok := st.sessions[st.activeSessionID]
	if !ok {
		return nil, false
	}
	if !sess.ClosingAt.IsZero() && now.After(sess.GraceUntil) {
		return nil, false
	}
	return sess, true
}

// expireSessionsLocked performs the actual janitor sweep. Sessions only leave
// memory after their grace period elapses; at that point they are finalized,
// logged once, and detached from the active-session pointer.
func (st *SessionTracker) expireSessionsLocked(now time.Time) []ExpiredSession {
	var expired []ExpiredSession
	for id, sess := range st.sessions {
		if !sessionExpired(sess, now) {
			continue
		}
		closeAt := sess.GraceUntil
		if closeAt.IsZero() {
			closeAt = now
		}
		closeSessionLocked(sess, closeAt)
		expired = append(expired, ExpiredSession{
			ID:       sess.ID,
			ClosedAt: closeAt,
		})
		delete(st.sessions, id)
		if st.activeSessionID == id {
			st.activeSessionID = 0
		}
	}
	return expired
}

// closeSessionLocked is the terminal transition. After this point the session
// no longer accepts events and only its persisted logs remain.
func closeSessionLocked(sess *Session, closedAt time.Time) {
	if sess == nil {
		return
	}
	log.Printf(
		"[SESSION] end id=%d cli_pid=%d closed_at=%s",
		sess.ID,
		sess.SessionPID,
		closedAt.Format(time.RFC3339Nano),
	)
}

// markSessionClosing starts the post-exit grace window so late-arriving root
// or child events can still be attached to the same CLI invocation.
func markSessionClosing(sess *Session, closedAt time.Time) {
	if sess == nil || !sess.ClosingAt.IsZero() {
		return
	}
	sess.ClosingAt = closedAt
	sess.GraceUntil = closedAt.Add(sessionGracePeriod)
}

// sessionExpired reports whether the grace window is fully over and the
// janitor should permanently close and evict the session.
func sessionExpired(sess *Session, now time.Time) bool {
	if sess == nil {
		return true
	}
	if sess.ClosingAt.IsZero() {
		return false
	}
	return now.After(sess.GraceUntil)
}

// isOpenClawCLIInvocation identifies the execve that starts a user-facing
// OpenClaw CLI conversation and therefore defines a new evaluation session.
func isOpenClawCLIInvocation(e event.Event) bool {
	if e.Type != event.EventExecve {
		return false
	}

	args := e.Args
	base := strings.ToLower(filepath.Base(strings.TrimSpace(e.Path)))

	hasOpenClaw := base == "openclaw" || containsArgBase(args, "openclaw")
	hasAgent := containsArg(args, "agent")
	hasAgentFlag := containsArg(args, "--agent")
	hasMessageFlag := containsArg(args, "-m") || containsArg(args, "--message")

	return hasOpenClaw && hasAgent && hasAgentFlag && hasMessageFlag
}

func containsArgBase(args []string, target string) bool {
	for _, a := range args {
		a = strings.TrimSpace(a)
		if strings.ToLower(filepath.Base(a)) == target {
			return true
		}
	}
	return false
}