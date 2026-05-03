package context

import (
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

func TestSessionSnapshotPreservesPerProcessExecutionAndCapabilityInputs(t *testing.T) {
	now := time.Now()
	state := &SessionState{
		ID: 7,
		Processes: map[uint32]*ProcessState{
			200: {
				PID:      200,
				PPID:     100,
				UID:      501,
				ExecPath: "/bin/sh",
				LastSeen: now,
				Lineage:  []LineageNode{{PID: 200, PPID: 100, Comm: "sh"}},
				Security: &process.SecuritySnapshot{Available: true, CapEffMask: 1 << 13, SeccompMode: 2},
			},
			100: {
				PID:      100,
				PPID:     1,
				UID:      501,
				ExecPath: "/usr/bin/curl",
				LastSeen: now.Add(-time.Second),
				Lineage:  []LineageNode{{PID: 100, PPID: 1, Comm: "curl"}},
				Security: &process.SecuritySnapshot{Available: true, CapEffMask: 0, SeccompMode: 2},
			},
		},
	}

	snapshot := state.snapshot()
	if snapshot.ID != 7 {
		t.Fatalf("unexpected session id: %d", snapshot.ID)
	}
	if got := len(snapshot.Processes); got != 2 {
		t.Fatalf("expected 2 processes in snapshot, got %d", got)
	}
	first := BuildExecutionChainContext(snapshot.Processes[100])
	second := BuildExecutionChainContext(snapshot.Processes[200])
	if !first.NetworkToolInChain || !second.ShellInChain {
		t.Fatalf("expected per-process execution derivation to remain available from snapshot data")
	}

	firstCap := BuildCapabilityContext(snapshot.Processes[100])
	secondCap := BuildCapabilityContext(snapshot.Processes[200])
	if firstCap.DangerousCount != 0 || secondCap.DangerousCount != 1 {
		t.Fatalf("expected per-process capability derivation to remain available from snapshot data")
	}
}

func TestBuildHistoricalContextKeepsHistorySessionScoped(t *testing.T) {
	now := time.Now()
	state := &SessionState{
		ID: 9,
		RecentEvents: []ObservedEvent{
			{Type: 1, PID: 100, Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241, Time: now},
			{Type: 0, PID: 200, Path: "/tmp/openclaw-eval/backdoor.sh", Time: now.Add(time.Second)},
		},
		Processes: map[uint32]*ProcessState{
			100: {
				PID: 100,
				Opens: []ObservedOpen{
					{Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241, Time: now},
				},
			},
			200: {
				PID:      200,
				ExecPath: "/tmp/openclaw-eval/backdoor.sh",
			},
		},
	}

	history := BuildHistoricalContext(state.snapshot())
	if !history.WriteThenExecSamePath {
		t.Fatalf("expected session-scoped history to see cross-process write-then-exec")
	}
}

func TestApplyEventUpdatesExecCapabilityAndHistoryAggregates(t *testing.T) {
	now := time.Now()
	manager := NewManager()
	securityStore := process.NewSecurityStore()

	sessionID := process.SessionID(42)
	manager.sessions[sessionID] = &SessionState{
		ID:        uint32(sessionID),
		Processes: map[uint32]*ProcessState{},
		CreatedAt: now,
		UpdatedAt: now,
	}
	manager.contexts[sessionID] = &ContextSnapshot{
		SessionID: uint32(sessionID),
		CreatedAt: now,
		UpdatedAt: now,
	}

	manager.sessions[sessionID].Processes[100] = &ProcessState{
		PID:          100,
		ExecPath:     "/tmp/payload.sh",
		LineageDepth: 5,
		Lineage: []LineageNode{
			{PID: 100, PPID: 10, Comm: "sh"},
		},
		Security: &process.SecuritySnapshot{
			Available:   true,
			CapEffMask:  1 << 13,
			SeccompMode: 0,
		},
	}
	manager.sessions[sessionID].RecentEvents = []ObservedEvent{
		{Type: event.EventOpenat, PID: 100, Path: "/tmp/payload.sh", Flags: 0x241, Time: now},
		{Type: event.EventExecve, PID: 100, Path: "/tmp/payload.sh", Time: now.Add(time.Second)},
	}
	manager.sessions[sessionID].UpdatedAt = now.Add(time.Second)

	snapshot, ok := manager.ApplyEvent(sessionID, event.Event{Type: event.EventExecve, PID: 100})
	if !ok {
		t.Fatalf("expected apply event to find existing session")
	}
	if !snapshot.Execution.SuspiciousPathExec || !snapshot.Execution.ShellInChain || !snapshot.Execution.DeepChain {
		t.Fatalf("expected exec aggregate to be updated from process state")
	}
	if !snapshot.Capability.HasDangerousCaps || snapshot.Capability.DangerousCount != 1 || !snapshot.Capability.SeccompDisabled {
		t.Fatalf("expected capability aggregate to be updated from process security state")
	}
	if !snapshot.History.WriteThenExecSamePath {
		t.Fatalf("expected history aggregate to be recomputed from session history")
	}
	_ = securityStore
}

func TestApplyEventOpenOnlyUpdatesHistoryAggregate(t *testing.T) {
	now := time.Now()
	manager := NewManager()

	sessionID := process.SessionID(77)
	manager.sessions[sessionID] = &SessionState{
		ID:        uint32(sessionID),
		Processes: map[uint32]*ProcessState{},
		CreatedAt: now,
		UpdatedAt: now,
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, PID: 100, Path: "/etc/shadow", Time: now},
			{Type: event.EventConnect, PID: 100, Addr: "8.8.8.8", Port: 443, Time: now.Add(time.Second)},
		},
	}
	manager.contexts[sessionID] = &ContextSnapshot{
		SessionID: uint32(sessionID),
		CreatedAt: now,
		UpdatedAt: now,
	}

	snapshot, ok := manager.ApplyEvent(sessionID, event.Event{Type: event.EventOpenat, PID: 100})
	if !ok {
		t.Fatalf("expected apply event to find existing session")
	}
	if snapshot.Execution.SuspiciousPathExec || snapshot.Execution.ShellInChain || snapshot.Capability.HasDangerousCaps {
		t.Fatalf("expected open event not to mutate execution/capability aggregates")
	}
	if !snapshot.History.SensitiveThenNetwork {
		t.Fatalf("expected history aggregate to be updated for open/connect sequence")
	}
}

func TestPruneTransparentRoutineShellRemovesShellArtifacts(t *testing.T) {
	now := time.Now()
	manager := NewManager()
	sessionID := process.SessionID(88)
	manager.sessions[sessionID] = &SessionState{
		ID: uint32(sessionID),
		Processes: map[uint32]*ProcessState{
			100: {
				PID:      100,
				Comm:     "sh",
				ExecPath: "/bin/sh",
			},
		},
		RecentEvents: []ObservedEvent{
			{Type: event.EventExecve, PID: 100, Path: "/bin/sh", Time: now},
			{Type: event.EventExit, PID: 100, Time: now.Add(time.Second)},
		},
		CreatedAt: now,
		UpdatedAt: now.Add(time.Second),
	}

	if !manager.ObserveIgnored(sessionID, event.Event{
		Type: event.EventExecve,
		PID:  200,
		PPID: 100,
		Path: "/usr/bin/ip",
		Args: []string{"ip", "neigh", "show"},
	}) {
		t.Fatalf("expected transparent routine shell to be pruned")
	}
	raw, ok := manager.SnapshotSessionByID(sessionID)
	if !ok {
		t.Fatalf("expected raw session to remain available")
	}
	if len(raw.Processes) != 0 {
		t.Fatalf("expected shell process to be removed from raw session")
	}
	if len(raw.RecentEvents) != 0 {
		t.Fatalf("expected shell recent events to be removed from raw session")
	}
}

func TestApplyEventRebuildsExecutionAfterTransparentShellPrune(t *testing.T) {
	now := time.Now()
	manager := NewManager()
	sessionID := process.SessionID(89)
	manager.sessions[sessionID] = &SessionState{
		ID: uint32(sessionID),
		Processes: map[uint32]*ProcessState{
			100: {
				PID:          100,
				Comm:         "sh",
				ExecPath:     "/bin/sh",
				LineageDepth: 3,
				Lineage: []LineageNode{
					{PID: 1, Comm: "openclaw-gateway"},
					{PID: 50, Comm: "sh"},
				},
			},
			200: {
				PID:      200,
				Comm:     "mkdir",
				ExecPath: "/usr/bin/mkdir",
			},
		},
		RecentEvents: []ObservedEvent{
			{Type: event.EventExecve, PID: 100, Path: "/bin/sh", Time: now},
			{Type: event.EventExecve, PID: 200, Path: "/usr/bin/mkdir", Time: now.Add(time.Second)},
		},
		CreatedAt: now,
		UpdatedAt: now.Add(time.Second),
	}
	manager.contexts[sessionID] = &ContextSnapshot{
		SessionID:  uint32(sessionID),
		CreatedAt:  now,
		UpdatedAt:  now.Add(time.Second),
		Execution:  BuildExecutionChainContext(manager.sessions[sessionID].Processes[100]),
		Capability: CapabilityContext{CapabilityUnknown: true},
	}

	if !manager.ObserveIgnored(sessionID, event.Event{
		Type: event.EventExecve,
		PID:  300,
		PPID: 100,
		Path: "/usr/bin/ip",
		Args: []string{"ip", "neigh", "show"},
	}) {
		t.Fatalf("expected transparent routine shell to be pruned")
	}

	snapshot, ok := manager.ApplyEvent(sessionID, event.Event{Type: event.EventExecve, PID: 200})
	if !ok {
		t.Fatalf("expected apply event to find existing session")
	}
	if snapshot.Execution.ShellInChain || snapshot.Execution.DeepChain {
		t.Fatalf("expected execution aggregate to be rebuilt without shell wrapper pollution")
	}
}
