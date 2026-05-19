package pipeline

import (
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

type pendingShellWrappers struct {
	mu    sync.Mutex
	items map[process.SessionID]map[uint32]pendingShellWrapper
}

type pendingShellWrapper struct {
	PID       uint32
	PPID      uint32
	CreatedAt time.Time
}

func newPendingShellWrappers() *pendingShellWrappers {
	return &pendingShellWrappers{
		items: make(map[process.SessionID]map[uint32]pendingShellWrapper),
	}
}

func (p *pendingShellWrappers) Add(sessionID process.SessionID, e event.Event) {
	if p == nil || e.PID == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.items[sessionID]; !ok {
		p.items[sessionID] = make(map[uint32]pendingShellWrapper)
	}
	p.items[sessionID][e.PID] = pendingShellWrapper{
		PID:       e.PID,
		PPID:      e.PPID,
		CreatedAt: e.Time,
	}
}

func (p *pendingShellWrappers) Remove(sessionID process.SessionID, pid uint32) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(sessionID, pid)
}

func (p *pendingShellWrappers) ClearSession(sessionID process.SessionID) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.items, sessionID)
}

func (p *pendingShellWrappers) removeLocked(sessionID process.SessionID, pid uint32) {
	shells := p.items[sessionID]
	if shells == nil {
		return
	}
	delete(shells, pid)
	if len(shells) == 0 {
		delete(p.items, sessionID)
	}
}

func (p *pendingShellWrappers) PromoteIfMeaningful(sessionID process.SessionID, e event.Event, tracker *process.Tracker) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	shells := p.items[sessionID]
	if shells == nil {
		return false
	}
	if _, ok := shells[e.PID]; !ok {
		return false
	}
	if isPendingShellNoise(e) {
		return false
	}
	delete(shells, e.PID)
	if len(shells) == 0 {
		delete(p.items, sessionID)
	}
	if tracker != nil {
		tracker.SetTransparent(e.PID, false)
	}
	return true
}

func isPendingShellExecve(e event.Event) bool {
	if e.Type != event.EventExecve {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(e.Path)))
	switch base {
	case "sh", "bash", "dash", "zsh":
		return len(normalizeExecArgs(e.Args)) == 0
	default:
		return false
	}
}

func normalizeExecArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	trimmed := make([]string, 0, len(args))
	for _, arg := range args {
		value := strings.TrimSpace(arg)
		if value != "" {
			trimmed = append(trimmed, value)
		}
	}
	if len(trimmed) == 0 {
		return nil
	}
	if len(trimmed) == 1 {
		base := strings.ToLower(filepath.Base(trimmed[0]))
		switch base {
		case "sh", "bash", "dash", "zsh":
			return nil
		}
	}
	return trimmed
}

func isPendingShellNoise(e event.Event) bool {
	if e.Type == event.EventExit {
		return true
	}
	if e.Type == event.EventOpenat {
		return !ShouldIngestIntoContext(e)
	}
	return false
}
