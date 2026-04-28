package pipeline

import (
	"log"

	"github.com/cclts/casa/user/internal/audit"
	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

// Run is the main user-space analysis loop. It enriches events with process state,
// derives context, evaluates risk, and writes audit records.
func Run(events <-chan event.Event, decisionEngine *decision.Engine, auditMonitor *audit.Monitor) {
	tracker := process.NewTracker()
	sessionTracker := process.NewSessionTracker(tracker)
	securityStore := process.NewSecurityStore()
	contextManager := context.NewManager()

	if err := process.BootstrapOpenClaw(tracker, securityStore); err != nil {
		log.Println("bootstrap error:", err)
	}

	log.Println("bootstrap done")

	// Process incoming events from the eBPF ring buffer.
	for e := range events {
		if err := auditMonitor.RecordEvent(e); err != nil {
			log.Printf("Audit: event_write_failed err=%v", err)
		}

		// Tracking: Update the process lineage tree
		// On new process execution, propagate the tracking status from parent to child.
		if e.Type == event.EventExecve {
			tracker.Propagate(e.PID, e.PPID, e.Comm, isTransparentRoutineExec(e))
		}

		// Skip events if neither the process nor its parent is in our watchlist.
		if !tracker.Exists(e.PID) && !tracker.Exists(e.PPID) {
			auditMonitor.DiscardEvent(e)
			continue
		}

		// Resolve the event into the coarse "worker session" boundary the system uses today.
		sess, lineage, ok := sessionTracker.ResolveSession(
			e.PID,
			e.Time,
			decisionEngine.LineageMaxDepth(),
		)
		if !ok {
			auditMonitor.DiscardEvent(e)
			continue
		}

		if e.Type != event.EventExit {
			securityStore.Ensure(e.PID)
		}
		
		switch e.Type {
		case event.EventExecve:
			fullArgs := ""
			if len(e.Args) > 0 {
				fullArgs = strings.Join(e.Args, " ")
			}

			log.Printf("  ➤ Exec: %s", e.Path)
			if fullArgs != "" {
				log.Printf("  ➤ Args: %s", fullArgs)
			}

		case event.EventOpenat:
			log.Printf("  ➤ Open: %s flags=0x%x mode=0%o", e.Path, e.Flags, e.Mode)
		case event.EventConnect:
			log.Printf("  ➤ Connect: %s:%d", e.Addr, e.Port)
		case event.EventExit:
			log.Printf("  ➤ Exit: pid=%d tid=%d", e.PID, e.TID)
		}

		// The tracker caches parent/child depth so later stages do not have to re-walk /proc.
		info, _ := tracker.GetInfo(e.PID)
		if e.Type != event.EventExit && !ShouldIngestIntoContext(e) {
			auditMonitor.DiscardEvent(e)
			continue
		}
		ctx := contextManager.ObserveAndBuild(sess.SessionPID, lineage, securityStore, e, info.Depth)
		rawSession, ok := contextManager.SnapshotSession(sess.SessionPID)
		if !ok {
			auditMonitor.DiscardEvent(e)
			continue
		}
		result := decisionEngine.Evaluate(ctx)

		// Audit output is best-effort: analysis should continue even if disk logging fails.
		if err := auditMonitor.Record(e, ctx, rawSession, result); err != nil {
			log.Printf("Audit: write_failed err=%v", err)
		}

		if e.Type == event.EventExit {
			sessionTracker.HandleExit(e.PID, e.Time)
			tracker.Remove(e.PID)
		}
	}
}
