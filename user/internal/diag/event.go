package diag

import (
	"fmt"
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

	loggedAtNS := loggedAt.UnixNano()
	eventToLogMS := 0.0
	kernelToNormalizeMS := 0.0
	if !e.Time.IsZero() {
		eventNS := e.Time.UnixNano()
		eventToLogMS = msDelta(loggedAtNS, eventNS)
		kernelToNormalizeMS = msDelta(e.Latency.NormalizedAtNS, eventNS)
	}

	Logf("[LATENCY INTERNAL] pid=%d tid=%d ppid=%d session=%d type=%s ktime_ns=%d event_to_log_ms=%.3f kernel_to_normalize_ms=%.3f normalize_ms=%.3f event_ch_block_ms=%.3f event_ch_wait_ms=%.3f gate_ms=%.3f context_ms=%.3f decision_ms=%.3f audit_wait_ms=%.3f write_ms=%.3f accepted_to_log_ms=%.3f",
		e.PID,
		e.TID,
		e.PPID,
		sessionID,
		e.Type.String(),
		e.KTimeNS,
		eventToLogMS,
		kernelToNormalizeMS,
		msDelta(e.Latency.NormalizeSendStartNS, e.Latency.NormalizedAtNS),
		msDelta(e.Latency.NormalizeSendDoneNS, e.Latency.NormalizeSendStartNS),
		msDelta(e.Latency.PipelineRecvNS, e.Latency.NormalizeSendDoneNS),
		msDelta(e.Latency.GatePassedNS, e.Latency.PipelineRecvNS),
		msDelta(e.Latency.ContextAppliedNS, e.Latency.GatePassedNS),
		msDelta(e.Latency.DecisionDoneNS, e.Latency.ContextAppliedNS),
		msDelta(e.Latency.MonitorLockedNS, e.Latency.AuditCallNS),
		msDelta(loggedAtNS, e.Latency.MonitorLockedNS),
		msDelta(loggedAtNS, e.Latency.GatePassedNS),
	)
}

func EventFields(e event.Event) string {
	return fmt.Sprintf("pid=%d tid=%d ppid=%d type=%s ktime_ns=%d", e.PID, e.TID, e.PPID, e.Type.String(), e.KTimeNS)
}
