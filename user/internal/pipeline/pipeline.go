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
	"github.com/cclts/casa/user/internal/telemetry"
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
func Run(ctx stdcontext.Context, events <-chan event.Event, decisionEngine *decision.Engine, auditMonitor *audit.Monitor, providerClassifier *provider.Classifier, traceManager *telemetry.Manager) {
	tracker := process.NewTracker()
	sessionTracker := process.NewSessionTracker()
	securityStore := process.NewSecurityStore()
	contextManager := context.NewManager()
	pendingShells := newPendingShellWrappers()
	sessionTracker.StartJanitor(ctx, 500*time.Millisecond, func(id process.SessionID, closedAt time.Time) {
		traceManager.CloseSession(id, closedAt)
		contextManager.CloseSession(id, closedAt)
		pendingShells.ClearSession(id)
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

	for e := range events {
		e.Latency.EventSendDoneAt = time.Now()
		e.Latency.EventSendDoneAt = time.Now()

		if e.Type == event.EventExecve {
			tracker.Propagate(e.PID, e.PPID, isTransparentRoutineExec(e))
			sessionTracker.ObserveExecve(e)
		} else if e.Type == event.EventExit {
			sessionTracker.ObserveExit(e)
		}

		if !tracker.Exists(e.PID) && !tracker.Exists(e.PPID) {
			if e.Type == event.EventExit && e.PID == e.TID {
				tracker.Remove(e.PID)
			}
			continue
		}

		sess, ok := sessionTracker.ActiveSession(e.Time)
		if !ok {
			if e.Type == event.EventExit && e.PID == e.TID {
				tracker.Remove(e.PID)
			}
			continue
		}

		if pendingShells.PromoteIfMeaningful(sess.ID, e, tracker) {
			// The shell has now shown security-relevant behavior. Keep later events
			// visible, but do not synthesize its placeholder execve into context.
		}

		if isPendingShellExecve(e) {
			pendingShells.Add(sess.ID, e)
			tracker.SetTransparent(e.PID, true)
			continue
		}

		if shouldIgnoreSecurityPipelineEvent(e, sess.ID, contextManager, tracker, providerClassifier) {
			if e.Type == event.EventExit && e.PID == e.TID {
				pendingShells.Remove(sess.ID, e.PID)
			}
			if e.Type == event.EventExit && e.PID == e.TID {
				tracker.Remove(e.PID)
			}
			continue
		}

		var lineage process.Lineage
		if e.Type == event.EventExecve {
			securityStore.Ensure(e.PID)
			lineage = process.BuildLineage(e.PID, tracker, decisionEngine.LineageMaxDepth())
		}

		contextManager.Observe(sess.ID, lineage, securityStore, e)
		ctxSnapshot, ctxOK := contextManager.ApplyEvent(sess.ID, e)
		if ctxOK {
			if rawSession, rawOK := contextManager.SnapshotSessionByID(sess.ID); rawOK {
				result := decisionEngine.Evaluate(ctxSnapshot)
				recordOutcome, err := auditMonitor.Record(e, &rawSession, &result)
				if err != nil {
					log.Printf("Audit: write_failed err=%v", err)
				}
				traceManager.RecordAnalysis(telemetry.AnalysisInput{
					Session: sess,
					Event:   e,
					Context: ctxSnapshot,
					Result:  result,
					Audit:   recordOutcome,
				})
			}
		}

		if e.Type == event.EventExit && e.PID == e.TID {
			pendingShells.Remove(sess.ID, e.PID)
			tracker.Remove(e.PID)
		}
	}
}
