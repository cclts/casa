package process

// Node is a single point in the ancestry chain used for lineage reporting.
type Node struct {
	PID  int
	PPID int
}

// Lineage is ordered from the target process upward toward the tracked root.
type Lineage struct {
	Nodes []Node
}

// BuildLineage walks parent processes using only the tracker cache.
func BuildLineage(pid int, tracker *Tracker, maxDepth int) Lineage {
	var nodes []Node
	current := pid

	for i := 0; i < maxDepth + 1; i++ {
		info, ok := tracker.GetInfo(uint32(current))
		if !ok {
			break
		}

		if !info.Transparent {
			nodes = append(nodes, Node{
				PID:  current,
				PPID: int(info.PPID),
			})
		}

		if tracker.IsRoot(uint32(current)) {
			break
		}

		current = int(info.PPID)
	}

	return Lineage{
		Nodes: nodes,
	}
}
