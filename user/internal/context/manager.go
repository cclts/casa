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
	recentEventLimit int
}

// NewManager creates the in-memory session store used by context generation.
func NewManager() *Manager {
	return &Manager{
		sessions:         make(map[process.SessionID]*SessionState),
		contexts:         make(map[process.SessionID]*ContextSnapshot),
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
	procRecord.PPID = e.PPID
	procRecord.UID = e.UID
	if procRecord.Comm == "" {
		procRecord.Comm = e.Comm
	}
	procRecord.LastSeen = e.Time

	switch e.Type {
	case event.EventExecve:
		depth := lineageDepth(lineage)
		procRecord.ExecPath = e.Path
		procRecord.Comm = basenameFromPath(e.Path)
		procRecord.Args = append([]string(nil), e.Args...)
		procRecord.LineageDepth = depth
		procRecord.Lineage = rebuildLineage(session, procRecord, lineage)
		procRecord.ExitTime = time.Time{}
		if securityStore != nil {
			if snapshot, ok := securityStore.Get(e.PID); ok {
				procRecord.Security = snapshot
			}
		}
	case event.EventOpenat:
		procRecord.Opens = append(procRecord.Opens, ObservedOpen{
			Path:  e.Path,
			Flags: e.Flags,
			Mode:  e.Mode,
			Time:  e.Time,
		})
		procRecord.Opens = trimOpenEvents(procRecord.Opens)
	case event.EventConnect:
		procRecord.Connects = append(procRecord.Connects, ObservedConnect{
			Endpoint: Endpoint{
				Addr: e.Addr,
				Port: e.Port,
			},
			Time: e.Time,
		})
		procRecord.Connects = trimConnectEvents(procRecord.Connects)
	case event.EventExit:
		procRecord.ExitTime = e.Time
	}

	session.RecentEvents = append(session.RecentEvents, ObservedEvent{
		Type:  e.Type,
		PID:   e.PID,
		Path:  e.Path,
		Flags: e.Flags,
		Mode:  e.Mode,
		Addr:  e.Addr,
		Port:  e.Port,
		Time:  e.Time,
	})
	session.RecentEvents = trimRecentEvents(session.RecentEvents, m.recentEventLimit)
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

	ctxState.UpdatedAt = session.UpdatedAt
	if !session.ClosedAt.IsZero() {
		ctxState.ClosedAt = session.ClosedAt
	}

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

func lineageDepth(lineage process.Lineage) int {
	if len(lineage.Nodes) == 0 {
		return 0
	}
	return len(lineage.Nodes) - 1
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

// CloseSession marks one session closed at the supplied time without mutating
// any per-process raw facts.
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
}

// rebuildLineage converts the process package's lineage model into the context-local shape.
func rebuildLineage(session *SessionState, procRecord *ProcessState, lineage process.Lineage) []LineageNode {
	if len(lineage.Nodes) == 0 {
		return nil
	}

	out := make([]LineageNode, 0, len(lineage.Nodes))
	for _, n := range lineage.Nodes {
		comm := ""
		switch {
		case procRecord != nil && n.PID == procRecord.PID:
			if procRecord.ExecPath != "" {
				comm = basenameFromPath(procRecord.ExecPath)
			} else {
				comm = procRecord.Comm
			}
		case session != nil:
			if ancestor := session.Processes[n.PID]; ancestor != nil {
				if ancestor.ExecPath != "" {
					comm = basenameFromPath(ancestor.ExecPath)
				} else {
					comm = ancestor.Comm
				}
			}
		}

		out = append(out, LineageNode{
			PID:  n.PID,
			PPID: n.PPID,
			Comm: comm,
		})
	}
	return out
}

func updateExecutionAggregate(dst *ExecutionChainContext, src ExecutionChainContext) {
	dst.SuspiciousPathExec = dst.SuspiciousPathExec || src.SuspiciousPathExec
	dst.DeepChain = dst.DeepChain || src.DeepChain
	dst.ShellInChain = dst.ShellInChain || src.ShellInChain
	dst.NetworkToolInChain = dst.NetworkToolInChain || src.NetworkToolInChain
	dst.InterpreterInChain = dst.InterpreterInChain || src.InterpreterInChain
	dst.ContainerRuntimeInChain = dst.ContainerRuntimeInChain || src.ContainerRuntimeInChain
	dst.MemfdOrDeletedExec = dst.MemfdOrDeletedExec || src.MemfdOrDeletedExec
}

func updateCapabilityAggregate(dst *CapabilityContext, src CapabilityContext) {
	dst.CapabilityUnknown = dst.CapabilityUnknown || src.CapabilityUnknown
	if src.DangerousCount > dst.DangerousCount {
		dst.DangerousCount = src.DangerousCount
	}
	dst.HasDangerousCaps = dst.HasDangerousCaps || src.HasDangerousCaps
	dst.SeccompDisabled = dst.SeccompDisabled || src.SeccompDisabled
}

func cloneContextSnapshot(src *ContextSnapshot) ContextSnapshot {
	if src == nil {
		return ContextSnapshot{}
	}
	return *src
}
