package process

import (
	"sync"
)

// TrackedInfo is the cached process metadata used to avoid repeated /proc reads.
type TrackedInfo struct {
	PPID        uint32
	Depth       int
	Transparent bool
}

// Tracker stores the subset of the process tree that the pipeline cares about.
type Tracker struct {
	mu      sync.RWMutex
	tracked map[uint32]TrackedInfo
	roots   map[uint32]struct{}
}

// NewTracker creates an empty process tracker.
func NewTracker() *Tracker {
	return &Tracker{
		tracked: make(map[uint32]TrackedInfo),
		roots:   make(map[uint32]struct{}),
	}
}

// IsRoot reports whether the pid is one of the bootstrapped tracking roots.
func (t *Tracker) IsRoot(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.roots[pid]
	return ok
}

// AddRoot marks a pid as a root process for lineage termination.
func (t *Tracker) AddRoot(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roots[pid] = struct{}{}
}

// Add inserts or updates cached process metadata.
func (t *Tracker) Add(pid uint32, ppid uint32, depth int, transparent bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked[pid] = TrackedInfo{
		PPID:        ppid,
		Depth:       depth,
		Transparent: transparent,
	}
}

// Exists reports whether a pid has been seen by the tracker.
func (t *Tracker) Exists(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.tracked[pid]
	return ok
}

// SetTransparent updates whether a tracked pid should be skipped in visible lineage.
func (t *Tracker) SetTransparent(pid uint32, transparent bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, ok := t.tracked[pid]
	if !ok {
		return
	}
	info.Transparent = transparent
	t.tracked[pid] = info
}

// GetInfo returns cached process metadata if present.
func (t *Tracker) GetInfo(pid uint32) (TrackedInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	info, ok := t.tracked[pid]
	if !ok {
		return TrackedInfo{}, false
	}
	return info, true
}

// EventDepth returns the tracked depth for an event pid, falling back to the
// parent depth plus one when only the parent is currently cached.
func (t *Tracker) EventDepth(pid uint32, ppid uint32) int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if info, ok := t.tracked[pid]; ok {
		return info.Depth
	}
	if info, ok := t.tracked[ppid]; ok {
		return info.Depth + 1
	}
	return 0
}

// Propagate seeds a child entry from its parent's cached depth when an execve arrives.
func (t *Tracker) Propagate(pid uint32, ppid uint32, transparent bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parent, ok := t.tracked[ppid]
	if !ok {
		return
	}

	depth := parent.Depth + 1
	if transparent {
		depth = parent.Depth
	}

	t.tracked[pid] = TrackedInfo{
		PPID:        ppid,
		Depth:       depth,
		Transparent: transparent,
	}
}

// Remove drops a pid from the tracker so exited processes do not leak stale lineage.
func (t *Tracker) Remove(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.tracked, pid)
	delete(t.roots, pid)
}
