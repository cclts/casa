package process

import (
	"log"

	"github.com/cclts/care-go/user/internal/proc"
)

// Node is a single point in the ancestry chain used for lineage reporting.
type Node struct {
	PID  int
	PPID int
	Comm string
	Path string
	UID  int
}

// Lineage is ordered from the target process upward toward the tracked root.
type Lineage struct {
	Nodes []Node
}

// BuildLineage walks parent processes using the tracker cache first and /proc as fallback.
func BuildLineage(pid int, tracker *Tracker, maxDepth int) Lineage {
	var nodes []Node
	current := pid

	for i := 0; i < maxDepth; i++ {
		// Check the Tracker cache first.
		if info, ok := tracker.GetInfo(uint32(current)); ok {
			nodes = append(nodes, Node{
				PID:  current,
				PPID: int(info.PPID),
				Comm: info.Comm,
			})

			// Stop tracing if reached the root process (e.g., OpenClaw Gateway).
			if tracker.IsRoot(uint32(current)) {
				break
			}

			// Move up to the parent process.
			current = int(info.PPID)

			continue
		}

		// Fallback to the Linux /proc filesystem.
		// This handles "pre-existing" processes that started before bootstrap.
		comm, err := proc.ReadComm(current)
		if err != nil {
			break
		}

		ppid, err := proc.ReadPPID(current)
		if err != nil {
			break
		}

		nodes = append(nodes, Node{
			PID:  current,
			PPID: ppid,
			Comm: comm,
		})

		// Add the process into Tracker cache.
		depth := 0
		if parent, ok := tracker.GetInfo(uint32(ppid)); ok {
			depth = parent.Depth + 1
		}

		tracker.Add(uint32(current), uint32(ppid), comm, depth)
		log.Printf("[DEBUG] Fallback hit: Discovered pre-existing process %d (%s), adding to tracker", current, comm)

		// Stop tracing if reached the root process (e.g., OpenClaw Gateway).
		if tracker.IsRoot(uint32(current)) {
			break
		}

		// Move up to the parent process.
		current = ppid
	}

	return Lineage{
		Nodes: nodes,
	}
}
