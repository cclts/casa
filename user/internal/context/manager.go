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

// ObserveAndBuild folds one normalized event into session state and returns the updated context snapshot.
func (m *Manager) ObserveAndBuild(
	sessionID uint32,
	lineage process.Lineage,
	securityStore *process.SecurityStore,
	e event.Event,
	depth int,
) Context {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.sessions[sessionID]
	if !ok {
		session = newSessionState(sessionID, e.Time)
		m.sessions[sessionID] = session
	}

	session.UpdatedAt = e.Time
	if depth > session.MaxLineageDepth {
		session.MaxLineageDepth = depth
	}

	procRecord := session.getOrCreateProcess(e.PID, e.Time)
	procRecord.PPID = e.PPID
	procRecord.UID = e.UID
	if procRecord.Comm == "" {
		procRecord.Comm = e.Comm
	}
	procRecord.LineageDepth = depth
	procRecord.LastSeen = e.Time
	procRecord.Lineage = rebuildLineage(lineage)
	if e.Type != event.EventExit {
		procRecord.ExitSeen = false
		procRecord.ExitTime = time.Time{}
	}
	if securityStore != nil {
		if snapshot, ok := securityStore.Get(e.PID); ok {
			procRecord.Security = snapshot
		}
	}

	switch e.Type {
	case event.EventExecve:
		procRecord.ExecPath = e.Path
		procRecord.Comm = basenameFromPath(e.Path)
		procRecord.Args = append([]string(nil), e.Args...)
		procRecord.ExecCount++
		session.Counts.Execs++
	case event.EventOpenat:
		procRecord.OpenCount++
		session.Counts.Opens++
		procRecord.Opens = append(procRecord.Opens, ObservedOpen{
			Path:  e.Path,
			Flags: e.Flags,
			Mode:  e.Mode,
			Time:  e.Time,
		})
		procRecord.Opens = trimOpenEvents(procRecord.Opens)
	case event.EventConnect:
		procRecord.ConnectCount++
		session.Counts.Connects++
		procRecord.Connects = append(procRecord.Connects, ObservedConnect{
			Endpoint: Endpoint{
				Addr: e.Addr,
				Port: e.Port,
			},
			Time: e.Time,
		})
		procRecord.Connects = trimConnectEvents(procRecord.Connects)
		session.UniqueConnectEndpoints = appendUniqueEndpoint(session.UniqueConnectEndpoints, Endpoint{
			Addr: e.Addr,
			Port: e.Port,
		})
	case event.EventExit:
		procRecord.ExitSeen = true
		procRecord.ExitTime = e.Time
		if e.PID == sessionID || session.allProcessesExited() {
			session.IsClosed = true
			session.ClosedAt = e.Time
		}
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

	return BuildContext(session, e.PID)
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
