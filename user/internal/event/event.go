package event

type EventType int

const (
    EventExecve EventType = iota 
    EventOpenat
    EventConnect
)

type Event struct {
    PID  uint32
    PPID uint32
    UID  uint32

    Comm string
    Path string

    Addr string
    Port uint32

    Type EventType
}