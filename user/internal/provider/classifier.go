package provider

import (
	"log"

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
		ignored := info.Depth == 0
		log.Printf("[PROVIDER CONNECT] pid=%d ppid=%d addr=%s port=%d matched=true depth=%d ignored=%t", e.PID, e.PPID, e.Addr, e.Port, info.Depth, ignored)
		return ignored
	}

	parent, ok := tracker.GetInfo(e.PPID)
	if ok {
		ignored := parent.Depth == 0
		log.Printf("[PROVIDER CONNECT] pid=%d ppid=%d addr=%s port=%d matched=true parent_depth=%d ignored=%t", e.PID, e.PPID, e.Addr, e.Port, parent.Depth, ignored)
		return ignored
	}

	log.Printf("[PROVIDER CONNECT] pid=%d ppid=%d addr=%s port=%d matched=true ignored=false reason=no_tracker_info", e.PID, e.PPID, e.Addr, e.Port)
	return false
}
