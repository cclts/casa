package provider

import (
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

type Classifier struct {
	endpoints EndpointSet
}

func NewClassifier(endpoints EndpointSet) *Classifier {
	return &Classifier{endpoints: endpoints}
}

func (c *Classifier) ShouldIgnoreProviderConnect(e event.Event, tracker *process.Tracker) bool {
	if c == nil || tracker == nil {
		return false
	}
	if !c.endpoints.ContainsConnect(e) {
		return false
	}

	info, ok := tracker.GetInfo(e.PID)
	if ok {
		return info.Depth == 0
	}

	parent, ok := tracker.GetInfo(e.PPID)
	if ok {
		return parent.Depth == 0
	}

	return false
}
