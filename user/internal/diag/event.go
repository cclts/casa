package diag

import (
	"time"

	"github.com/cclts/casa/user/internal/event"
)

func msDelta(endNS, startNS int64) float64 {
	if endNS <= 0 || startNS <= 0 || endNS < startNS {
		return 0
	}
	return float64(endNS-startNS) / 1_000_000
}

func LogInternalLatency(e event.Event, sessionID uint32, loggedAt time.Time) {
	if !Enabled() {
		return
	}

	eventToLogMS := 0.0
	kernelToRingbufMS := 0.0
	if !e.Time.IsZero() {
		eventNS := e.Time.UnixNano()
		eventToLogMS = msDelta(loggedAt.UnixNano(), eventNS)
		kernelToRingbufMS = msDelta(e.Latency.RingbufReadNS, eventNS)
	}

	Logf("[LATENCY INTERNAL] pid=%d tid=%d ppid=%d session=%d type=%s ktime_ns=%d event_to_log_ms=%.3f kernel_to_ringbuf_ms=%.3f raw_queue_ms=%.3f normalize_ms=%.3f event_ch_block_ms=%.3f",
		e.PID,
		e.TID,
		e.PPID,
		sessionID,
		e.Type.String(),
		e.KTimeNS,
		eventToLogMS,
		kernelToRingbufMS,
		msDelta(e.Latency.RawRecvNS, e.Latency.RawSendStartNS),
		msDelta(e.Latency.NormalizeDoneNS, e.Latency.RawRecvNS),
		msDelta(e.Latency.EventSendDoneNS, e.Latency.EventSendStartNS),
	)
}
