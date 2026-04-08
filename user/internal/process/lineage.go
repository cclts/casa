package process

import (
	"log"

	"github.com/cclts/care-go/user/internal/proc"
)

type Node struct {
	PID  int
	PPID int
	Comm string
	Path string
	UID  int
}

type Lineage struct {
	Nodes []Node
	Depth int
}

const MaxDepth = 4

func BuildLineage(pid int, tracker *Tracker) Lineage {
	var nodes []Node
	current := pid

	for i := 0; i < MaxDepth; i++ {
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
		tracker.Add(uint32(current), uint32(ppid), comm)
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
		Depth: len(nodes),
	}
}
