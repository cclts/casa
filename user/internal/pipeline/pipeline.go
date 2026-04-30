package pipeline

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/cclts/casa/user/internal/audit"
	casacontext "github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

// Run is the main user-space analysis loop.
// It keeps four responsibilities separate:
// 1. stage every raw event for events.log
// 2. maintain tracker/session lifecycle state
// 3. derive context only for events that belong to the active CLI session
// 4. evaluate and emit higher-level audit/session records
func Run(ctx context.Context, events <-chan event.Event, decisionEngine *decision.Engine, auditMonitor *audit.Monitor) {
	tracker := process.NewTracker()
	sessionTracker := process.NewSessionTracker(tracker)
	sessionTracker.StartJanitor(ctx, 500*time.Millisecond)
	securityStore := process.NewSecurityStore()
	contextManager := casacontext.NewManager()

	if err := process.BootstrapOpenClaw(tracker, securityStore); err != nil {
		log.Println("bootstrap error:", err)
	}

	log.Println("bootstrap done")

	// Process incoming events from the eBPF ring buffer.
	for e := range events {
		if err := auditMonitor.RecordEvent(e); err != nil {
			log.Printf("Audit: event_write_failed err=%v", err)
		}

		// Execve is the only point where tracker depth propagation and session
		// start detection happen. Other syscalls reuse the already-known tree.
		if e.Type == event.EventExecve {
			tracker.Propagate(e.PID, e.PPID, isTransparentRoutineExec(e))
			sessionTracker.ObserveExecve(e)
		} else if e.Type == event.EventExit {
			// log.Printf("[RAW EXIT] pid=%d ppid=%d comm=%q", e.PID, e.PPID, e.Comm)
			sessionTracker.ObserveExit(e)
		}

		// First gate: keep only events from the tracked OpenClaw process tree.
		if !tracker.Exists(e.PID) && !tracker.Exists(e.PPID) {
			auditMonitor.DiscardEvent(e)
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}

		// Second gate: within the OpenClaw tree, keep only events that belong
		// to an active CLI invocation session.
		sess, ok := sessionTracker.Resolve(e)
		if !ok {
			auditMonitor.DiscardEvent(e)
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}

		// Security posture is sampled lazily on execve so later opens/connects for
		// the same pid can reuse the cached snapshot.
		if e.Type == event.EventExecve {
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

		// Non-EXIT noise stays in events.log only; it does not pollute session raw state.
		if e.Type != event.EventExit && !ShouldIngestIntoContext(e) {
			auditMonitor.DiscardEvent(e)
			continue
		}

		info, _ := tracker.GetInfo(e.PID)
		lineage := process.BuildLineage(e.PID, tracker, decisionEngine.LineageMaxDepth())
		contextSnapshot := contextManager.ObserveAndBuild(sess.ID, lineage, securityStore, e, info.Depth)
		if e.Type == event.EventExit && e.PID == sess.SessionPID {
			contextManager.CloseSession(sess.ID, e.Time)
		}
		rawSession, ok := contextManager.SnapshotSessionByID(sess.ID)
		if !ok {
			auditMonitor.DiscardEvent(e)
			continue
		}
		result := decisionEngine.Evaluate(contextSnapshot)

		// Audit output is best-effort: analysis should continue even if disk logging fails.
		if err := auditMonitor.Record(e, contextSnapshot, rawSession, result); err != nil {
			log.Printf("Audit: write_failed err=%v", err)
		}

		if e.Type == event.EventExit {
			tracker.Remove(e.PID)
		}
	}
}
