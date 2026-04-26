package pipeline

import (
	"log"
	"strings"

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
		// Tracking: Update the process lineage tree
		// On new process execution, propagate the tracking status from parent to child.
		if e.Type == event.EventExecve {
			tracker.Propagate(e.PID, e.PPID, e.Comm)
		}

		// Skip events if neither the process nor its parent is in our watchlist.
		if !tracker.Exists(e.PID) && !tracker.Exists(e.PPID) {
			continue
		}

		// Resolve the event into the coarse "worker session" boundary the system uses today.
		sess, lineage, ok := sessionTracker.ResolveSession(
			e.PID,
			e.Time,
			decisionEngine.LineageMaxDepth(),
		)
		if !ok {
			continue
		}

		if e.Type != event.EventExit {
			securityStore.Ensure(e.PID)
		}

		// The tracker caches parent/child depth so later stages do not have to re-walk /proc.
		info, _ := tracker.GetInfo(e.PID)
		ctx := contextManager.ObserveAndBuild(sess.SessionPID, lineage, securityStore, e, info.Depth)
		result := decisionEngine.Evaluate(ctx)
		log.Printf("[%s] (Time: %s PID: %d, Depth: %d, Session %d)", e.Type, e.TimeHuman, e.PID, info.Depth, sess.ID)

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
		// Print lineage inline because it is often the fastest way to explain suspicious ancestry.
		for i, n := range lineage.Nodes {
			prefix := "  ↳"
			if i == 0 {
				prefix = "  [Target]"
			}
			indent := strings.Repeat("    ", i)
			log.Printf("%s%s %d (%s)", indent, prefix, n.PID, n.Comm)
		}

		log.Printf("  • Context Exec: binary=%s uid=%d depth=%d suspicious_path=%v",
			ctx.Execution.BinaryPath,
			ctx.Execution.UID,
			ctx.Execution.ChainDepth,
			ctx.Execution.SuspiciousPathExec,
		)
		log.Printf("  • Context Caps: danger=%v seccomp_enabled=%v unknown=%v",
			ctx.Capability.DangerousCaps,
			!ctx.Capability.SeccompDisabled,
			ctx.Capability.CapabilityUnknown,
		)
		log.Printf("  • Context History: exec=%d open=%d connect=%d connect_then_exec=%v sensitive_then_net=%v sensitive_then_execve=%v burst_connect=%v burst_exec=%v unique_open_paths=%d",
			ctx.History.ExecCount,
			ctx.History.OpenCount,
			ctx.History.ConnectCount,
			ctx.History.ConnectThenExec,
			ctx.History.SensitiveThenNetwork,
			ctx.History.SensitiveThenExecve,
			ctx.History.BurstConnect,
			ctx.History.BurstExec,
			ctx.History.UniqueOpenPathCount,
		)
		log.Printf("  • Context File: write_then_exec_same_path=%v opened_deleted_path=%v",
			ctx.File.WriteThenExecSamePath,
			ctx.File.OpenedDeletedPath,
		)
		log.Printf("  • Decision: action=%s score=%d thresholds(log=%d alert=%d) rules=%v",
			result.Action,
			result.Score,
			result.LogThreshold,
			result.AlertThreshold,
			result.Triggered,
		)

		// Audit output is best-effort: analysis should continue even if disk logging fails.
		if err := auditMonitor.Record(e, ctx, result); err != nil {
			log.Printf("  • Audit: write_failed err=%v", err)
		}

		if e.Type == event.EventExit {
			sessionTracker.HandleExit(e.PID, e.Time)
			tracker.Remove(e.PID)
		}
	}
}
