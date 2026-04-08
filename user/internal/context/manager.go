// package context

// import (
// 	"log"
// 	"sync"
// 	"time"

// 	"github.com/cclts/care-go/user/internal/event"
// 	"github.com/cclts/care-go/user/internal/process"
// )

// type Manager struct {
// 	mu sync.Mutex

// 	// rootPID → session(graph)
// 	sessions map[uint32]*Session

// 	tracker *process.Tracker
// 	timeout time.Duration
// }

// func NewManager(tracker *process.Tracker, timeout time.Duration) *Manager {
// 	m := &Manager{
// 		sessions: make(map[uint32]*Session),
// 		tracker:  tracker,
// 		timeout:  timeout,
// 	}

// 	go m.gcLoop()
// 	return m
// }

// // =====================
// // Entry
// // =====================

// func (m *Manager) HandleEvent(e event.Event) {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()

// 	root := m.findRoot(e.PID)

// 	s, ok := m.sessions[root]
// 	if !ok {
// 		s = NewSession(root)
// 		m.sessions[root] = s
// 	}

// 	switch e.Type {

// 	case event.EventExecve:
// 		lineage := process.BuildLineage(int(e.PID), m.tracker)

// 		s.AddExec(
// 			e.PID,
// 			e.PPID,
// 			e.Comm,
// 			e.Path,
// 			e.Args,
// 			e.UID,
// 			lineage,
// 		)

// 	case event.EventOpenat:
// 		s.AddOpen(e.PID, e.Path)

// 	case event.EventConnect:
// 		s.AddConnect(e.PID, e.Addr, e.Port)
// 	}
// }

// func (m *Manager) gcLoop() {
// 	ticker := time.NewTicker(2 * time.Second)
// 	defer ticker.Stop()

// 	for range ticker.C {
// 		m.gc()
// 	}
// }

// func (m *Manager) gc() {
// 	m.mu.Lock()
// 	defer m.mu.Unlock()

// 	now := time.Now()

// 	for root, s := range m.sessions {
// 		if now.Sub(s.LastSeen) > m.timeout {

// 			ctx := BuildContext(s)

// 			m.emit(s, ctx)
// 			delete(m.sessions, root)
// 		}
// 	}
// }

// func (m *Manager) emit(s *Session, ctx Context) {

// 	log.Println("====== SESSION ======")
// 	log.Printf("Root: %d Nodes: %d", s.Root.PID, len(s.Nodes))

// 	log.Printf("Depth: %d SuspiciousPath: %v Chain: %v",
// 		ctx.Execution.Depth,
// 		ctx.Execution.SuspiciousPath,
// 		ctx.Execution.SuspiciousChain,
// 	)

// 	log.Printf("Connect→Exec: %v Sensitive→Connect: %v",
// 		ctx.History.ConnectThenExec,
// 		ctx.History.SensitiveThenConnect,
// 	)
// }
