package ebpf

import (
	"bytes"
	"net"
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/proc"
)

// ToEvent converts the fixed-width ring buffer payload into the internal event model.
func ToEvent(e Event) event.Event {
	ip := net.IPv4(
		byte(e.Daddr),
		byte(e.Daddr>>8),
		byte(e.Daddr>>16),
		byte(e.Daddr>>24),
	)

	// Args are copied out of the fixed-size kernel payload and truncated to the
	// maximum argument slots that the eBPF side exports.
	args := make([]string, 0, e.Argc)
	for i := 0; i < int(e.Argc); i++ {
		if i >= len(e.Args) {
			break
		}
		argStr := string(bytes.TrimRight(e.Args[i][:], "\x00"))
		args = append(args, argStr)
	}

	port := (e.Dport << 8) | (e.Dport >> 8)
	eventTime, err := proc.EventTimeFromKtime(e.TsNS)
	if err != nil {
		eventTime = time.Time{}
	}

	return event.Event{
		PID:  e.Tgid,
		TID:  e.Pid,
		PPID: e.Ppid,
		UID:  e.Uid,

		Addr: ip.String(),
		Port: port,

		Comm: string(bytes.TrimRight(e.Comm[:], "\x00")),
		Path: string(bytes.TrimRight(e.Filename[:], "\x00")),
		Args: args,
		Flags: e.Flags,
		Mode:  e.Mode,

		KTimeNS:   e.TsNS,
		Time:      eventTime,
		TimeHuman: proc.FormatEventTime(eventTime),

		Type: mapEventType(e.Type),
	}
}

// mapEventType keeps the raw eBPF event identifiers isolated from the rest of the codebase.
func mapEventType(t uint32) event.EventType {
	switch t {
	case 0:
		return event.EventExecve
	case 1:
		return event.EventOpenat
	case 2:
		return event.EventConnect
	case 3:
		return event.EventExit
	default:
		return event.EventExecve
	}
}
