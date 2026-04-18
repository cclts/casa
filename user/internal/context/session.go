package context

// import (
// 	"time"

// 	"github.com/cclts/care-go/user/internal/process"
// )

// // =====================
// // Node (Process Node)
// // =====================

// type ProcNode struct {
// 	PID  uint32
// 	PPID uint32

// 	Comm string
// 	Path string
// 	UID  uint32

// 	// execution info
// 	ExecPath string
// 	Args     []string
// 	HasExec  bool

// 	// behavior on this node
// 	Opens    []string
// 	Connects []ConnEvent

// 	FirstSeen time.Time
// 	LastSeen  time.Time

// 	Parent   *ProcNode
// 	Children []*ProcNode
// }

// // =====================
// // Events
// // =====================

// type ConnEvent struct {
// 	Addr string
// 	Port uint32
// 	Time time.Time
// }

// // =====================
// // Session (Graph)
// // =====================

// type Session struct {
// 	Root *ProcNode

// 	// PID → node
// 	Nodes map[uint32]*ProcNode

// 	StartTime time.Time
// 	LastSeen  time.Time
// }

// // =====================
// // Constructor
// // =====================

// func NewSession(rootPID uint32) *Session {
// 	now := time.Now()

// 	root := &ProcNode{
// 		PID:       rootPID,
// 		FirstSeen: now,
// 		LastSeen:  now,
// 	}

// 	return &Session{
// 		Root:      root,
// 		Nodes:     map[uint32]*ProcNode{rootPID: root},
// 		StartTime: now,
// 		LastSeen:  now,
// 	}
// }

// // 確保 node 存在，並建立 parent-child 關係
// func (s *Session) ensureNode(pid, ppid uint32) *ProcNode {

// 	// 已存在
// 	if n, ok := s.Nodes[pid]; ok {
// 		return n
// 	}

// 	now := time.Now()

// 	n := &ProcNode{
// 		PID:       pid,
// 		PPID:      ppid,
// 		FirstSeen: now,
// 		LastSeen:  now,
// 	}

// 	s.Nodes[pid] = n

// 	// 建立 parent link
// 	if parent, ok := s.Nodes[ppid]; ok {
// 		n.Parent = parent
// 		parent.Children = append(parent.Children, n)
// 	}

// 	return n
// }

// func (s *Session) AddExec(
// 	pid, ppid uint32,
// 	comm string,
// 	path string,
// 	args []string,
// 	uid uint32,
// 	lineage process.Lineage,
// ) {

// 	n := s.ensureNode(pid, ppid)

// 	n.Comm = comm
// 	n.ExecPath = path
// 	n.Args = args
// 	n.UID = uid
// 	n.HasExec = true
// 	n.LastSeen = time.Now()

// 	// 👉 用 lineage 修正 parent 關係（避免 race / 遺失）
// 	s.rebuildFromLineage(lineage)

// 	s.LastSeen = time.Now()
// }

// func (s *Session) AddOpen(pid uint32, path string) {
// 	n := s.ensureNode(pid, 0)

// 	n.Opens = append(n.Opens, path)
// 	n.LastSeen = time.Now()

// 	s.LastSeen = n.LastSeen
// }

// func (s *Session) AddConnect(pid uint32, addr string, port uint32) {
// 	n := s.ensureNode(pid, 0)

// 	n.Connects = append(n.Connects, ConnEvent{
// 		Addr: addr,
// 		Port: port,
// 		Time: time.Now(),
// 	})

// 	n.LastSeen = time.Now()
// 	s.LastSeen = n.LastSeen
// }
