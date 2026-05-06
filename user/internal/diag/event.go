package diag

import (
	"time"

	"github.com/cclts/casa/user/internal/event"
)

func durationMS(end, start time.Time) float64 {
	if end.IsZero() || start.IsZero() || end.Before(start) {
		return 0
	}
	return float64(end.Sub(start)) / float64(time.Millisecond)
}

func LogInternalLatency(e event.Event, sessionID uint32, loggedAt time.Time) {
	if !Enabled() {
		return
	}

	Logf("[LATENCY INTERNAL] pid=%d tid=%d ppid=%d session=%d type=%s ktime_ns=%d userspace_total_ms=%.3f raw_queue_ms=%.3f normalize_ms=%.3f event_ch_block_ms=%.3f",
		e.PID,
		e.TID,
		e.PPID,
		sessionID,
		e.Type.String(),
		e.KTimeNS,
		durationMS(loggedAt, e.Latency.RingbufReadAt),
		durationMS(e.Latency.RawRecvAt, e.Latency.RawSendStartAt),
		durationMS(e.Latency.NormalizeDoneAt, e.Latency.RawRecvAt),
		durationMS(e.Latency.EventSendDoneAt, e.Latency.EventSendStartAt),
	)
}
