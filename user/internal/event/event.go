package event

import "time"

// EventType is the normalized event vocabulary used across the user-space pipeline.
type EventType int

const (
	EventExecve EventType = iota
	EventOpenat
	EventConnect
)

// String renders the event type in a log-friendly form.
func (t EventType) String() string {
	switch t {
	case EventExecve:
		return "EXECVE"
	case EventOpenat:
		return "OPENAT"
	case EventConnect:
		return "CONNECT"
	default:
		return "OTHER"
	}
}

// Event is the shared user-space representation after raw eBPF events are normalized.
type Event struct {
	PID  uint32 // This is TGID (Process ID)
	TID  uint32 // This is PID (Thread ID)
	PPID uint32
	UID  uint32

	Comm string
	Path string
	Args []string

	Addr string
	Port uint32

	KTimeNS   uint64
	Time      time.Time
	TimeHuman string

	Type EventType
}
