package context

import (
	"sync"
	"time"

	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/process"
)

type Manager struct {
	mu               sync.Mutex
	sessions         map[uint32]*SessionState
	recentEventLimit int
}

func NewManager() *Manager {
	return &Manager{
		sessions:         make(map[uint32]*SessionState),
		recentEventLimit: defaultRecentEventLimit,
	}
}

func (m *Manager) Observe(sessionID uint32, lineage process.Lineage, e event.Event, depth int) Context {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.sessions[sessionID]
	if !ok {
		state = newSessionState(sessionID)
		m.sessions[sessionID] = state
	}

	now := time.Now()
	state.UpdatedAt = now

	procState := state.ensureProcess(e.PID)
	procState.PPID = e.PPID
	procState.UID = e.UID
	procState.Comm = e.Comm
	procState.Depth = depth
	procState.LastSeen = now

	if procState.FirstSeen.IsZero() {
		procState.FirstSeen = now
	}

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
			Time: now,
		})
		procState.Opens = trimOpenEvents(procState.Opens)
	case event.EventConnect:
		procState.ConnectCount++
		procState.Connects = append(procState.Connects, ObservedConnect{
			Addr: e.Addr,
			Port: e.Port,
			Time: now,
		})
		procState.Connects = trimConnectEvents(procState.Connects)
	}

	state.RecentEvents = append(state.RecentEvents, ObservedEvent{
		Type: e.Type,
		PID:  e.PID,
		Path: e.Path,
		Addr: e.Addr,
		Port: e.Port,
		Time: now,
	})
	state.RecentEvents = trimRecentEvents(state.RecentEvents, m.recentEventLimit)

	return Build(state, e.PID)
}

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
