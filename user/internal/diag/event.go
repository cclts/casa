package diag

import (
	"fmt"
	"time"

	"github.com/cclts/casa/user/internal/event"
)

func EventFields(e event.Event) string {
	now := time.Now()
	fields := fmt.Sprintf(
		"ts=%s wall_ns=%d pid=%d tid=%d ppid=%d type=%s ktime_ns=%d",
		now.Format(time.RFC3339Nano),
		now.UnixNano(),
		e.PID,
		e.TID,
		e.PPID,
		e.Type.String(),
		e.KTimeNS,
	)
	if !e.Time.IsZero() {
		fields += fmt.Sprintf(
			" event_time=%s event_ns=%d event_to_now_ms=%.3f",
			e.Time.Format(time.RFC3339Nano),
			e.Time.UnixNano(),
			float64(now.UnixNano()-e.Time.UnixNano())/1_000_000,
		)
	}
	return fields
}

func EventStagef(stage string, e event.Event, format string, args ...any) {
	if !Enabled() {
		return
	}
	msg := ""
	if format != "" {
		msg = " " + fmt.Sprintf(format, args...)
	}
	Logf("[LATENCY DEBUG] stage=%s %s%s", stage, EventFields(e), msg)
}
