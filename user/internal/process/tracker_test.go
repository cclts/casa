package process

import "testing"

func TestTrackerPropagateAndRemove(t *testing.T) {
	tracker := NewTracker()
	tracker.Add(10, 1, 0, false)
	tracker.AddRoot(10)

	tracker.Propagate(20, 10, false)
	info, ok := tracker.GetInfo(20)
	if !ok {
		t.Fatalf("expected propagated child to be tracked")
	}
	if info.Depth != 1 || info.PPID != 10 {
		t.Fatalf("unexpected propagated child info: %+v", info)
	}

	tracker.Propagate(30, 20, true)
	info, ok = tracker.GetInfo(30)
	if !ok {
		t.Fatalf("expected transparent child to be tracked")
	}
	if info.Depth != 1 {
		t.Fatalf("expected transparent child to inherit depth, got %d", info.Depth)
	}

	tracker.Remove(10)
	if tracker.Exists(10) || tracker.IsRoot(10) {
		t.Fatalf("expected remove to clear tracked pid and root marker")
	}
}

func TestTrackerSetTransparentUpdatesVisibleLineage(t *testing.T) {
	tracker := NewTracker()
	tracker.Add(10, 1, 0, false)
	tracker.AddRoot(10)
	tracker.Add(20, 10, 1, false)
	tracker.Add(30, 20, 2, false)

	tracker.SetTransparent(20, true)

	lineage := BuildLineage(30, tracker, 4)
	if len(lineage.Nodes) != 2 {
		t.Fatalf("expected 2 visible lineage nodes, got %d", len(lineage.Nodes))
	}
	if lineage.Nodes[0].PID != 30 || lineage.Nodes[1].PID != 10 {
		t.Fatalf("unexpected lineage nodes after transparency update: %+v", lineage.Nodes)
	}
}

func TestBuildLineageSkipsTransparentNodes(t *testing.T) {
	tracker := NewTracker()
	tracker.Add(10, 1, 0, false)
	tracker.AddRoot(10)
	tracker.Add(20, 10, 1, true)
	tracker.Add(30, 20, 1, false)

	lineage := BuildLineage(30, tracker, 4)
	if len(lineage.Nodes) != 2 {
		t.Fatalf("expected 2 visible lineage nodes, got %d", len(lineage.Nodes))
	}
	if lineage.Nodes[0].PID != 30 || lineage.Nodes[1].PID != 10 {
		t.Fatalf("unexpected lineage nodes: %+v", lineage.Nodes)
	}
}
