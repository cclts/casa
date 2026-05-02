package pipeline

import (
	stdcontext "context"
	"log"
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
//  1. update only the minimal tracker/session lifecycle state
//  2. first gate: drop anything outside the tracked OpenClaw tree
//  3. write tree-scoped events.log records
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
		rawSession, ok := contextManager.SnapshotSessionByID(id)
		if !ok {
			decisionEngine.CloseSession(uint32(id))
			return
		}
		if err := auditMonitor.RecordSessionSnapshot(rawSession, "session_closed", closedAt); err != nil {
			log.Printf("Audit: session_write_failed err=%v", err)
		}
		decisionEngine.CloseSession(uint32(id))
	})

	if err := process.BootstrapOpenClaw(tracker, securityStore); err != nil {
		log.Println("bootstrap error:", err)
	}

	log.Println("bootstrap done")

	// Process incoming events from the eBPF ring buffer.
	for e := range events {
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
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}

		var (
			rawSession *context.SessionSnapshot
			result     *decision.Result
		)

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
		if ok {
			// Some known-noisy patterns still stay in events.log, but should not
			// mutate session raw state or derived context.
			if e.Type != event.EventExit && !ShouldIngestIntoContext(e) {
				contextManager.ObserveIgnored(sess.ID, e)
			} else if e.Type == event.EventExit && contextManager.ObserveIgnored(sess.ID, e) {
				// EXIT can still be used to clean up ignored routine wrappers.
			} else {
				contextManager.Observe(sess.ID, lineage, securityStore, e)
				ctxSnapshot, ctxOK := contextManager.ApplyEvent(sess.ID, e)
				if ctxOK {
					rawSessionValue, rawOK := contextManager.SnapshotSessionByID(sess.ID)
					if rawOK {
						resultValue := decisionEngine.Evaluate(ctxSnapshot)
						rawSession = &rawSessionValue
						result = &resultValue
					}
				}
			}
		}

		if err := auditMonitor.Record(e, rawSession, result); err != nil {
			log.Printf("Audit: write_failed err=%v", err)
		}

		if e.Type == event.EventExit {
			tracker.Remove(e.PID)
		}
	}
}
