package process

// Node is a single point in the ancestry chain used for lineage reporting.
type Node struct {
	PID  uint32
	PPID uint32
}

// Lineage is ordered from the target process upward toward the tracked root.
type Lineage struct {
	Nodes []Node
}

// BuildLineage walks parent processes using only the tracker cache.
func BuildLineage(pid uint32, tracker *Tracker, maxDepth int) Lineage {
	var nodes []Node
	current := pid

	for i := 0; i < maxDepth + 1; i++ {
		info, ok := tracker.GetInfo(current)
		if !ok {
			break
		}

		if !info.Transparent {
			nodes = append(nodes, Node{
				PID:  current,
				PPID: info.PPID,
			})
		}

		if tracker.IsRoot(current) {
			break
		}

		current = info.PPID
	}

	return Lineage{
		Nodes: nodes,
	}
}
