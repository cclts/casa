package event

type EventType int

const (
	EventExecve EventType = iota
	EventOpenat
	EventConnect
)

func (t EventType) String() string {
	switch t {
	case EventExecve:
		return "EXECVE"
	case EventOpenat:
		return "OPENAT"
	case EventConnect:
		return "CONNECT"
	default:
		return "UNKNOWN"
	}
}

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

	Type EventType
}
