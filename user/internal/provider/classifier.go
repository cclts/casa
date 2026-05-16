package provider

import (
	"strings"
	"sync"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

type Classifier struct {
	mu        sync.RWMutex
	endpoints EndpointSet
}

func NewClassifier(endpoints EndpointSet) *Classifier {
	return &Classifier{endpoints: endpoints}
}

func (c *Classifier) ShouldIgnoreConfiguredConnect(e event.Event, tracker *process.Tracker) bool {
	if c == nil || tracker == nil {
		return false
	}
	c.mu.RLock()
	endpoints := c.endpoints
	c.mu.RUnlock()
	if !endpoints.ContainsConnect(e) {
		return false
	}

	info, ok := tracker.GetInfo(e.PID)
	if ok {
		return info.Depth == 0 || isOpenClawRuntimeComm(e.Comm)
	}

	parent, ok := tracker.GetInfo(e.PPID)
	if ok {
		return parent.Depth == 0 || isOpenClawRuntimeComm(e.Comm)
	}

	return false
}

func isOpenClawRuntimeComm(comm string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(comm)), "openclaw")
}

func (c *Classifier) ReplaceEndpoints(endpoints EndpointSet) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.endpoints = endpoints
	c.mu.Unlock()
}
