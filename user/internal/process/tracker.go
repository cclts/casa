package process

import (
	"sync"
	"time"
)

const ttl = 5 * time.Second

// TrackedInfo caches process info to prevent race condition
type TrackedInfo struct {
	Comm      string
	PPID      uint32
	Timestamp time.Time
}

type Tracker struct {
	mu      sync.RWMutex
	tracked map[uint32]TrackedInfo
	roots   map[uint32]struct{}
}

func NewTracker() *Tracker {
	return &Tracker{
		tracked: make(map[uint32]TrackedInfo),
		roots:   make(map[uint32]struct{}),
	}
}

func (t *Tracker) IsRoot(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.roots[pid]
	return ok
}

func (t *Tracker) AddRoot(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.roots[pid] = struct{}{}
}

func (t *Tracker) Add(pid uint32, ppid uint32, comm string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked[pid] = TrackedInfo{
		Comm:      comm,
		PPID:      ppid,
		Timestamp: time.Now(),
	}
}

func (t *Tracker) Exists(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.tracked[pid]
	return ok
}

func (t *Tracker) IsFresh(pid uint32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, ok := t.tracked[pid]
	if !ok {
		return false
	}
	return time.Since(info.Timestamp) <= ttl
}

func (t *Tracker) GetInfo(pid uint32) (TrackedInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	info, ok := t.tracked[pid]
	if !ok || time.Since(info.Timestamp) > ttl {
		return TrackedInfo{}, false
	}
	return info, true
}

func (t *Tracker) Propagate(pid uint32, ppid uint32, comm string) {
	if t.Exists(ppid) {
		t.Add(pid, ppid, comm)
	}
}
