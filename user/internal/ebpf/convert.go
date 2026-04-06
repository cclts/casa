package ebpf

import (
	"bytes"
	"net"

	"github.com/cclts/care-go/user/internal/event"
)

func ToEvent(e Event) event.Event {
	ip := net.IPv4(
		byte(e.Daddr),
		byte(e.Daddr>>8),
		byte(e.Daddr>>16),
		byte(e.Daddr>>24),
	)

	port := (e.Dport << 8) | (e.Dport >> 8)

	return event.Event{
		PID:  e.Tgid,
		TID:  e.Pid,
		PPID: e.Ppid,
        UID:  e.Uid,
		
		Addr: ip.String(),
		Port: uint32(port),

		Comm: string(bytes.TrimRight(e.Comm[:], "\x00")),
		Path: string(bytes.TrimRight(e.Filename[:], "\x00")),

		Type: mapEventType(e.Type),
	}
}

func mapEventType(t uint32) event.EventType {
	switch t {
	case 0:
		return event.EventExecve
	case 1:
		return event.EventOpenat
	case 2:
		return event.EventConnect
	default:
		return event.EventExecve
	}
}