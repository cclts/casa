package context

import (
	"sync"

	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/process"
)

// Manager owns the mutable session state used to build context snapshots over time.
type Manager struct {
	mu               sync.Mutex
	sessions         map[uint32]*SessionState
	recentEventLimit int
}

// NewManager creates the in-memory session store used by context generation.
func NewManager() *Manager {
	return &Manager{
		sessions:         make(map[uint32]*SessionState),
		recentEventLimit: defaultRecentEventLimit,
	}
}

// Observe folds one normalized event into session state and returns the updated context snapshot.
func (m *Manager) Observe(sessionID uint32, lineage process.Lineage, e event.Event, depth int) Context {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.sessions[sessionID]
	if !ok {
		state = newSessionState(sessionID, e.Time)
		m.sessions[sessionID] = state
	}

	state.UpdatedAt = e.Time

	procState := state.ensureProcess(e.PID, e.Time)
	procState.PPID = e.PPID
	procState.UID = e.UID
	procState.Comm = e.Comm
	procState.Depth = depth
	procState.LastSeen = e.Time

	if procState.FirstSeen.IsZero() {
		procState.FirstSeen = e.Time
	}

	// Persist the freshest lineage view so later context builders can use a stable snapshot.
	procState.Lineage = rebuildLineage(lineage)

	switch e.Type {
	case event.EventExecve:
		procState.ExecPath = e.Path
		procState.Args = append([]string(nil), e.Args...)
		procState.ExecCount++
	case event.EventOpenat:
		procState.OpenCount++
		procState.Opens = append(procState.Opens, ObservedOpen{
			Path: e.Path,
			Time: e.Time,
		})
		procState.Opens = trimOpenEvents(procState.Opens)
	case event.EventConnect:
		procState.ConnectCount++
		procState.Connects = append(procState.Connects, ObservedConnect{
			Addr: e.Addr,
			Port: e.Port,
			Time: e.Time,
		})
		procState.Connects = trimConnectEvents(procState.Connects)
	}

	// Session history is kept separately from per-process artifacts because several
	// features reason about event ordering across the full session window.
	state.RecentEvents = append(state.RecentEvents, ObservedEvent{
		Type: e.Type,
		PID:  e.PID,
		Path: e.Path,
		Addr: e.Addr,
		Port: e.Port,
		Time: e.Time,
	})
	state.RecentEvents = trimRecentEvents(state.RecentEvents, m.recentEventLimit)

	return Build(state, e.PID)
}

// rebuildLineage converts the process package's lineage model into the context-local shape.
func rebuildLineage(lineage process.Lineage) []LineageNode {
	if len(lineage.Nodes) == 0 {
		return nil
	}

	out := make([]LineageNode, 0, len(lineage.Nodes))
	for _, n := range lineage.Nodes {
		out = append(out, LineageNode{
			PID:  uint32(n.PID),
			PPID: uint32(n.PPID),
			Comm: n.Comm,
		})
	}
	return out
}
