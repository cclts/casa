package process

import (
	"sync"

	"github.com/cclts/casa/user/internal/proc"
)

// SecuritySnapshot caches the last known security posture for a tracked pid.
// When Available is false, the snapshot is intentionally marked unknown.
type SecuritySnapshot struct {
	CapEffMask  uint64
	SeccompMode int
	Available   bool
	Error       string
}

// SecurityStore owns the security snapshot cache for tracked processes.
type SecurityStore struct {
	mu        sync.RWMutex
	snapshots map[uint32]*SecuritySnapshot
}

// NewSecurityStore creates an empty snapshot store.
func NewSecurityStore() *SecurityStore {
	return &SecurityStore{
		snapshots: make(map[uint32]*SecuritySnapshot),
	}
}

// Ensure returns the cached snapshot for a pid or creates it on first access.
func (s *SecurityStore) Ensure(pid uint32) *SecuritySnapshot {
	s.mu.RLock()
	snapshot, ok := s.snapshots[pid]
	s.mu.RUnlock()
	if ok {
		return cloneSecuritySnapshot(snapshot)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if snapshot, ok := s.snapshots[pid]; ok {
		return cloneSecuritySnapshot(snapshot)
	}

	snapshot = readSecuritySnapshot(pid)
	s.snapshots[pid] = snapshot
	return cloneSecuritySnapshot(snapshot)
}

// Get returns a copy of the cached snapshot if present.
func (s *SecurityStore) Get(pid uint32) (*SecuritySnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot, ok := s.snapshots[pid]
	if !ok {
		return nil, false
	}
	return cloneSecuritySnapshot(snapshot), true
}

func readSecuritySnapshot(pid uint32) *SecuritySnapshot {
	mask, seccompMode, err := proc.ReadProcSecurityDetails(int(pid))
	if err != nil {
		return &SecuritySnapshot{
			Available: false,
			Error:     err.Error(),
		}
	}

	return &SecuritySnapshot{
		CapEffMask:  mask,
		SeccompMode: seccompMode,
		Available:   true,
	}
}

func cloneSecuritySnapshot(snapshot *SecuritySnapshot) *SecuritySnapshot {
	if snapshot == nil {
		return nil
	}

	cloned := *snapshot
	return &cloned
}
