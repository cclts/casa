package pipeline

import (
	stdcontext "context"
	"log"
	"time"

	"github.com/cclts/casa/user/internal/audit"
	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/diag"
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
		diag.EventStagef("pipeline_recv", e, "event_queue_len=%d", len(events))

		// Execve is the only event that can extend the tracked tree and start a
		// new CLI session. EXIT only updates closing state for the current session.
		if e.Type == event.EventExecve {
			tracker.Propagate(e.PID, e.PPID, isTransparentRoutineExec(e))
			sessionTracker.ObserveExecve(e)
			diag.EventStagef("tracker_exec_observed", e, "tracked_pid=%t tracked_ppid=%t", tracker.Exists(e.PID), tracker.Exists(e.PPID))
		} else if e.Type == event.EventExit {
			sessionTracker.ObserveExit(e)
			diag.EventStagef("tracker_exit_observed", e, "tracked_pid=%t tracked_ppid=%t", tracker.Exists(e.PID), tracker.Exists(e.PPID))
		}

		// First gate: keep only events from the tracked OpenClaw process tree.
		if !tracker.Exists(e.PID) && !tracker.Exists(e.PPID) {
			diag.EventStagef("gate_tree_drop", e, "tracked_pid=%t tracked_ppid=%t", tracker.Exists(e.PID), tracker.Exists(e.PPID))
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}
		diag.EventStagef("gate_tree_pass", e, "tracked_pid=%t tracked_ppid=%t", tracker.Exists(e.PID), tracker.Exists(e.PPID))

		// Second gate: the event is already inside the tracked tree. The remaining
		// question is whether a CLI session window is active at this timestamp.
		sess, ok := sessionTracker.ActiveSession(e.Time)
		if !ok {
			diag.EventStagef("gate_session_drop", e, "reason=no_active_session")
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}
		diag.EventStagef("gate_session_pass", e, "session=%d", sess.ID)

		// Third gate: known-noisy patterns are excluded before any heavier
		// per-pid enrichment so they do not enter raw session state or derived
		// security context.
		if shouldIgnoreSecurityPipelineEvent(e, sess.ID, contextManager, tracker, providerClassifier) {
			diag.EventStagef("gate_ignore_drop", e, "session=%d", sess.ID)
			if e.Type == event.EventExit {
				tracker.Remove(e.PID)
			}
			continue
		}
		diag.EventStagef("gate_ignore_pass", e, "session=%d", sess.ID)

		// Heavier per-pid enrichment only happens for events that survive the
		// tree, session, and ignore gates. Today only execve needs these reads.
		var lineage process.Lineage
		if e.Type == event.EventExecve {
			securityStore.Ensure(e.PID)
			lineage = process.BuildLineage(e.PID, tracker, decisionEngine.LineageMaxDepth())
			diag.EventStagef("exec_enriched", e, "session=%d lineage_depth=%d", sess.ID, len(lineage.Nodes))
		}

		// The event has survived all gates, so it now becomes part of session raw
		// state and can contribute to derived security context.
		contextManager.Observe(sess.ID, lineage, securityStore, e)
		diag.EventStagef("context_observed", e, "session=%d", sess.ID)
		ctxSnapshot, ctxOK := contextManager.ApplyEvent(sess.ID, e)
		if ctxOK {
			diag.EventStagef("context_applied", e, "session=%d history=%+v", sess.ID, ctxSnapshot.History)
			// Audit/session output only happens after both the raw session snapshot
			// and derived decision result are available for the same event.
			if rawSession, rawOK := contextManager.SnapshotSessionByID(sess.ID); rawOK {
				result := decisionEngine.Evaluate(ctxSnapshot)
				diag.EventStagef("decision_done", e, "session=%d score=%d increment=%d action=%s triggered=%d", sess.ID, result.Score, result.Increment, result.Action, len(result.Triggered))
				diag.EventStagef("audit_record_start", e, "session=%d", sess.ID)
				if err := auditMonitor.Record(e, &rawSession, &result); err != nil {
					log.Printf("Audit: write_failed err=%v", err)
					diag.EventStagef("audit_record_failed", e, "session=%d err=%v", sess.ID, err)
				} else {
					diag.EventStagef("audit_record_done", e, "session=%d", sess.ID)
				}
			}
		}

		// EXIT is the last event we expect from this pid in the tracked tree, so
		// remove it after all session/context processing for this event is done.
		if e.Type == event.EventExit {
			tracker.Remove(e.PID)
			diag.EventStagef("tracker_exit_removed", e, "session=%d", sess.ID)
		}
	}
}
