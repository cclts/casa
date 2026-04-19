package process

import (
	"sync"
)

// TrackedInfo is the cached process metadata used to avoid repeated /proc reads.
type TrackedInfo struct {
	Comm  string
	PPID  uint32
	Depth int
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
func (t *Tracker) Add(pid uint32, ppid uint32, comm string, depth int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked[pid] = TrackedInfo{
		Comm:  comm,
		PPID:  ppid,
		Depth: depth,
	}
}

// Exists reports whether a pid has been seen by the tracker.
func (t *Tracker) Exists(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.tracked[pid]
	return ok
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

// Propagate seeds a child entry from its parent's cached depth when an execve arrives.
func (t *Tracker) Propagate(pid uint32, ppid uint32, comm string) {
	parent, ok := t.tracked[ppid]
	if !ok {
		return
	}

	t.tracked[pid] = TrackedInfo{
		Comm:  comm,
		PPID:  ppid,
		Depth: parent.Depth + 1,
	}
}
