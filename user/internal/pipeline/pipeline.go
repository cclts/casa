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
	"github.com/cclts/casa/user/internal/provider"
)

// Run is the main user-space analysis loop.
//
// Order matters here:
//  1. update only the minimal tracker/session lifecycle state
//  2. first gate: drop anything outside the tracked OpenClaw tree
//  3. second gate: require an active CLI session window
//  4. third gate: drop known-noisy events that should not enter the security pipeline
//  5. only then do heavier enrichment such as security reads and exec lineage
//  6. fold accepted events into raw session state
//  7. derive session context, evaluate rules, and emit logs
func Run(ctx stdcontext.Context, events <-chan event.Event, decisionEngine *decision.Engine, auditMonitor *audit.Monitor, providerClassifier *provider.Classifier) {
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

		// Second gate: the event is already inside the tracked tree. The remaining
		// question is whether a CLI session window is active at this timestamp.
		sess, ok := sessionTracker.ActiveSession(e.Time)
		if !ok {
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}

		// Third gate: known-noisy patterns are excluded before any heavier
		// per-pid enrichment so they do not enter raw session state or derived
		// security context.
		if shouldIgnoreSecurityPipelineEvent(e, sess.ID, contextManager, tracker, providerClassifier) {
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}

		// Heavier per-pid enrichment only happens for events that survive the
		// tree, session, and ignore gates. Today only execve needs these reads.
		var lineage process.Lineage
		if e.Type == event.EventExecve {
			securityStore.Ensure(e.PID)
			lineage = process.BuildLineage(e.PID, tracker, decisionEngine.LineageMaxDepth())
		}

		// The event has survived all gates, so it now becomes part of session raw
		// state and can contribute to derived security context.
		contextManager.Observe(sess.ID, lineage, securityStore, e)
		ctxSnapshot, ctxOK := contextManager.ApplyEvent(sess.ID, e)
		if ctxOK {
			// Audit/session output only happens after both the raw session snapshot
			// and derived decision result are available for the same event.
			if rawSession, rawOK := contextManager.SnapshotSessionByID(sess.ID); rawOK {
				result := decisionEngine.Evaluate(ctxSnapshot)
				if err := auditMonitor.Record(e, &rawSession, &result); err != nil {
					log.Printf("Audit: write_failed err=%v", err)
				}
			}
		}

		// EXIT is the last event we expect from this pid in the tracked tree, so
		// remove it after all session/context processing for this event is done.
		if e.Type == event.EventExit {
			tracker.Remove(e.PID)
		}
	}
}
