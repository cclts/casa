package pipeline

import (
	stdcontext "context"
	"log"
	"strings"
	"time"

	"github.com/cclts/casa/user/internal/audit"
	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

// Run is the main user-space analysis loop.
//
// Order matters here:
//  1. stage the raw event for events.log
//  2. update only the minimal tracker/session lifecycle state
//  3. first gate: drop anything outside the tracked OpenClaw tree
//  4. only after that, do heavier enrichment such as security reads and
//     exec lineage reconstruction
//  5. keep only events that occur while a CLI session window is active
//  6. fold accepted events into raw session state, derive session context, and
//     emit audit/session records
func Run(ctx stdcontext.Context, events <-chan event.Event, decisionEngine *decision.Engine, auditMonitor *audit.Monitor) {
	tracker := process.NewTracker()
	sessionTracker := process.NewSessionTracker()
	securityStore := process.NewSecurityStore()
	contextManager := context.NewManager()
	sessionTracker.StartJanitor(ctx, 500*time.Millisecond, func(id process.SessionID, closedAt time.Time) {
		contextManager.CloseSession(id, closedAt)
	})

	if err := process.BootstrapOpenClaw(tracker, securityStore); err != nil {
		log.Println("bootstrap error:", err)
	}

	log.Println("bootstrap done")

	// Process incoming events from the eBPF ring buffer.
	for e := range events {
		if err := auditMonitor.RecordEvent(e); err != nil {
			log.Printf("Audit: event_write_failed err=%v", err)
		}

		// Execve is the only event that can extend the tracked tree and start a
		// new CLI session. EXIT only updates closing state for the current session.
		if e.Type == event.EventExecve {
			tracker.Propagate(e.PID, e.PPID, isTransparentRoutineExec(e))
			sessionTracker.ObserveExecve(e)
		} else if e.Type == event.EventExit {
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

		// Heavier per-pid enrichment only happens after the tree-membership gate.
		// Today only execve needs these extra reads.
		var lineage process.Lineage
		if e.Type == event.EventExecve {
			securityStore.Ensure(e.PID)
			lineage = process.BuildLineage(e.PID, tracker, decisionEngine.LineageMaxDepth())
		}

		// SessionTracker only maintains the current CLI session window. Once the
		// event passed the tree-membership gate, the remaining question is whether
		// that session window is still active at this event timestamp.
		sess, ok := sessionTracker.ActiveSession(e.Time)
		if !ok {
			auditMonitor.DiscardEvent(e)
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
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

		// Some known-noisy patterns still stay in events.log, but should not
		// mutate session raw state or derived context.
		if e.Type != event.EventExit && !ShouldIngestIntoContext(e) {
			auditMonitor.DiscardEvent(e)
			continue
		}

		depth := tracker.EventDepth(e.PID, e.PPID)

		contextManager.Observe(sess.ID, lineage, securityStore, e)
		ctxSnapshot, ok := contextManager.ApplyEvent(sess.ID, e)
		if !ok {
			auditMonitor.DiscardEvent(e)
			continue
		}
		rawSession, ok := contextManager.SnapshotSessionByID(sess.ID)
		if !ok {
			auditMonitor.DiscardEvent(e)
			continue
		}
		result := decisionEngine.Evaluate(ctxSnapshot)

		// Audit output is best-effort; one failed sink write should not stop later
		// events from continuing through the analysis pipeline.
		if err := auditMonitor.Record(e, rawSession, depth, result); err != nil {
			log.Printf("Audit: write_failed err=%v", err)
		}

		if e.Type == event.EventExit {
			tracker.Remove(e.PID)
		}
	}
}
