package context

import (
	"sync"
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

// Manager owns the mutable session state used to build context snapshots over time.
type Manager struct {
	mu               sync.Mutex
	sessions         map[process.SessionID]*SessionState
	contexts         map[process.SessionID]*ContextSnapshot
	suppressedShells map[process.SessionID]map[uint32]struct{}
	recentEventLimit int
}

// NewManager creates the in-memory session store used by context generation.
func NewManager() *Manager {
	return &Manager{
		sessions:         make(map[process.SessionID]*SessionState),
		contexts:         make(map[process.SessionID]*ContextSnapshot),
		suppressedShells: make(map[process.SessionID]map[uint32]struct{}),
		recentEventLimit: CurrentHeuristics().RecentEventLimit,
	}
}

// Observe folds one normalized event into session state.
func (m *Manager) Observe(
	sessionID process.SessionID,
	lineage process.Lineage,
	securityStore *process.SecurityStore,
	e event.Event,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		session = newSessionState(uint32(sessionID), e.Time)
		m.sessions[sessionID] = session
		m.contexts[sessionID] = &ContextSnapshot{
			SessionID: uint32(sessionID),
			CreatedAt: e.Time,
			UpdatedAt: e.Time,
		}
	}

	session.UpdatedAt = e.Time

	procRecord := session.getOrCreateProcess(e.PID, e.Time)
	applyCommonProcessMetadata(procRecord, e)

	switch e.Type {
	case event.EventExecve:
		applyExecveToProcess(session, procRecord, lineage, securityStore, e)
	case event.EventOpenat:
		applyOpenatToProcess(procRecord, e)
	case event.EventConnect:
		applyConnectToProcess(procRecord, e)
	case event.EventExit:
		applyExitToProcess(procRecord, e)
	}

	appendRecentEvent(session, e, m.recentEventLimit)
}

// ObserveIgnored lets the manager normalize known session-level noise patterns
// even when the event itself should not be ingested into raw session state.
func (m *Manager) ObserveIgnored(sessionID process.SessionID, e event.Event) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return false
	}

	return normalizeIgnoredEvent(m.suppressedShells, sessionID, session, e)
}

// ApplyEvent updates the in-memory derived aggregate for one session and returns a snapshot.
func (m *Manager) ApplyEvent(sessionID process.SessionID, e event.Event) (ContextSnapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return ContextSnapshot{}, false
	}
	ctxState, ok := m.contexts[sessionID]
	if !ok {
		ctxState = &ContextSnapshot{
			SessionID: session.ID,
			CreatedAt: session.CreatedAt,
		}
		m.contexts[sessionID] = ctxState
	}

	syncContextTimestamps(ctxState, session)

	procState := session.Processes[e.PID]
	switch e.Type {
	case event.EventExecve:
		if procState != nil {
			updateExecutionAggregate(&ctxState.Execution, BuildExecutionChainContext(procState))
			updateCapabilityAggregate(&ctxState.Capability, BuildCapabilityContext(procState))
		}
	case event.EventExit:
		if procState != nil {
			updateExecutionAggregate(&ctxState.Execution, BuildExecutionChainContext(procState))
		}
	}

	ctxState.History = BuildHistoricalContext(session.snapshot())

	return cloneContextSnapshot(ctxState), true
}

// SnapshotSessionByID returns the current raw session snapshot for one session.
func (m *Manager) SnapshotSessionByID(sessionID process.SessionID) (SessionSnapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return SessionSnapshot{}, false
	}

	return session.snapshot(), true
}

func (m *Manager) CloseSession(sessionID process.SessionID, closedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		return
	}

	session.ClosedAt = closedAt
	session.UpdatedAt = closedAt
	if ctxState, ok := m.contexts[sessionID]; ok {
		ctxState.ClosedAt = closedAt
		ctxState.UpdatedAt = closedAt
	}
	delete(m.suppressedShells, sessionID)
}
