package context

import (
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/event"
)

func TestDetectWriteThenExecSamePathAcrossProcessesInSession(t *testing.T) {
	now := time.Now()
	state := &SessionState{
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, PID: 100, Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241, Time: now},
			{Type: event.EventExecve, PID: 101, Path: "/tmp/openclaw-eval/backdoor.sh", Time: now.Add(time.Second)},
		},
		Processes: map[uint32]*ProcessState{
			100: {
				PID: 100,
				Opens: []ObservedOpen{
					{Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241},
				},
			},
			101: {
				PID:      101,
				ExecPath: "/tmp/openclaw-eval/backdoor.sh",
			},
		},
	}

	if !detectWriteThenExecSamePath(state.snapshot()) {
		t.Fatalf("expected session-wide write-then-exec match across processes")
	}
}

func TestDetectWriteThenExecSamePathRequiresWriteIntent(t *testing.T) {
	now := time.Now()
	state := &SessionState{
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, PID: 100, Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0, Time: now},
			{Type: event.EventExecve, PID: 101, Path: "/tmp/openclaw-eval/backdoor.sh", Time: now.Add(time.Second)},
		},
		Processes: map[uint32]*ProcessState{
			100: {
				PID: 100,
				Opens: []ObservedOpen{
					{Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0},
				},
			},
			101: {
				PID:      101,
				ExecPath: "/tmp/openclaw-eval/backdoor.sh",
			},
		},
	}

	if detectWriteThenExecSamePath(state.snapshot()) {
		t.Fatalf("expected read-only open not to trigger write-then-exec")
	}
}

func TestDetectWriteThenExecSamePathRequiresWriteBeforeExec(t *testing.T) {
	now := time.Now()
	state := &SessionState{
		RecentEvents: []ObservedEvent{
			{Type: event.EventExecve, PID: 101, Path: "/tmp/openclaw-eval/backdoor.sh", Time: now},
			{Type: event.EventOpenat, PID: 100, Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241, Time: now.Add(time.Second)},
		},
	}

	if detectWriteThenExecSamePath(state.snapshot()) {
		t.Fatalf("expected exec before write not to trigger write-then-exec")
	}
}

func TestBuildHistoricalContextIncludesSessionScopedFileSignals(t *testing.T) {
	now := time.Now()
	state := &SessionState{
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, PID: 100, Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241, Time: now},
			{Type: event.EventExecve, PID: 101, Path: "/tmp/openclaw-eval/backdoor.sh", Time: now.Add(time.Second)},
		},
		Processes: map[uint32]*ProcessState{
			100: {
				PID: 100,
				Opens: []ObservedOpen{
					{Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241, Time: now},
					{Path: "/tmp/ghost (deleted)", Flags: 0, Time: now},
				},
			},
			101: {
				PID:      101,
				ExecPath: "/tmp/openclaw-eval/backdoor.sh",
			},
		},
	}

	history := BuildHistoricalContext(state.snapshot())
	if !history.WriteThenExecSamePath {
		t.Fatalf("expected write_then_exec_same_path to be present in history")
	}
	if !history.OpenedDeletedPath {
		t.Fatalf("expected opened_deleted_path to be present in history")
	}
}

func TestDetectConnectThenExecRespectsOrder(t *testing.T) {
	now := time.Now()
	if !detectConnectThenExec(SessionSnapshot{RecentEvents: []ObservedEvent{
		{Type: event.EventConnect, Time: now},
		{Type: event.EventExecve, Time: now.Add(time.Second)},
	}}) {
		t.Fatalf("expected connect followed by exec to trigger")
	}

	if detectConnectThenExec(SessionSnapshot{RecentEvents: []ObservedEvent{
		{Type: event.EventExecve, Time: now},
		{Type: event.EventConnect, Time: now.Add(time.Second)},
	}}) {
		t.Fatalf("expected exec before connect not to trigger")
	}
}

func TestDetectSensitiveThenNetworkIsSessionScoped(t *testing.T) {
	now := time.Now()
	state := &SessionState{
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, PID: 100, Path: "/etc/shadow", Time: now},
			{Type: event.EventConnect, PID: 200, Addr: "8.8.8.8", Port: 443, Time: now.Add(time.Second)},
		},
	}

	if !detectSensitiveThenNetwork(state.snapshot()) {
		t.Fatalf("expected sensitive open followed by later network activity in same session to trigger")
	}
}

func TestDetectSensitiveThenExecveRespectsWindowAndOrder(t *testing.T) {
	original := CurrentHeuristics()
	ConfigureHeuristics(Heuristics{
		RecentEventLimit:       original.RecentEventLimit,
		MaxPerProcessArtifacts: original.MaxPerProcessArtifacts,
		DeepChainThreshold:     original.DeepChainThreshold,
		BurstConnectThreshold:  original.BurstConnectThreshold,
		BurstExecThreshold:     original.BurstExecThreshold,
		BurstWindow:            original.BurstWindow,
		SensitiveHistoryWindow: 2 * time.Second,
		SuspiciousPathPatterns: original.SuspiciousPathPatterns,
		SensitivePathPrefixes:  original.SensitivePathPrefixes,
		SensitivePathPatterns:  original.SensitivePathPatterns,
		ShellNames:             original.ShellNames,
		NetworkToolNames:       original.NetworkToolNames,
		InterpreterNames:       original.InterpreterNames,
		ContainerRuntimeNames:  original.ContainerRuntimeNames,
	})
	defer ConfigureHeuristics(original)

	now := time.Now()
	if !detectSensitiveThenExecve(SessionSnapshot{RecentEvents: []ObservedEvent{
		{Type: event.EventOpenat, Path: "/etc/shadow", Time: now},
		{Type: event.EventExecve, Path: "/bin/sh", Time: now.Add(time.Second)},
	}}) {
		t.Fatalf("expected sensitive open followed by exec within window to trigger")
	}

	if detectSensitiveThenExecve(SessionSnapshot{RecentEvents: []ObservedEvent{
		{Type: event.EventExecve, Path: "/bin/sh", Time: now},
		{Type: event.EventOpenat, Path: "/etc/shadow", Time: now.Add(time.Second)},
	}}) {
		t.Fatalf("expected exec before sensitive open not to trigger")
	}

	if detectSensitiveThenExecve(SessionSnapshot{RecentEvents: []ObservedEvent{
		{Type: event.EventOpenat, Path: "/etc/shadow", Time: now},
		{Type: event.EventExecve, Path: "/bin/sh", Time: now.Add(3 * time.Second)},
	}}) {
		t.Fatalf("expected exec outside sensitive history window not to trigger")
	}
}

func TestDetectBurstEventForOpenHonorsIgnoreList(t *testing.T) {
	original := CurrentHeuristics()
	ConfigureHeuristics(Heuristics{
		RecentEventLimit:       original.RecentEventLimit,
		MaxPerProcessArtifacts: original.MaxPerProcessArtifacts,
		DeepChainThreshold:     original.DeepChainThreshold,
		BurstOpenThreshold:     3,
		BurstConnectThreshold:  original.BurstConnectThreshold,
		BurstExecThreshold:     original.BurstExecThreshold,
		BurstWindow:            2 * time.Second,
		SensitiveHistoryWindow: original.SensitiveHistoryWindow,
		SuspiciousPathPatterns: original.SuspiciousPathPatterns,
		SensitivePathPrefixes:  original.SensitivePathPrefixes,
		SensitivePathPatterns:  original.SensitivePathPatterns,
		ShellNames:             original.ShellNames,
		NetworkToolNames:       original.NetworkToolNames,
		InterpreterNames:       original.InterpreterNames,
		ContainerRuntimeNames:  original.ContainerRuntimeNames,
	})
	defer ConfigureHeuristics(original)

	now := time.Now()
	sessState := SessionSnapshot{
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, Path: "/etc/ld.so.cache", Time: now},
			{Type: event.EventOpenat, Path: "/home/ubuntu/.nvm/versions/node/v24.14.1/lib/node_modules/openclaw/package.json", Time: now.Add(200 * time.Millisecond)},
			{Type: event.EventOpenat, Path: "/home/ubuntu/.openclaw/config.json", Time: now.Add(400 * time.Millisecond)},
		},
	}
	if detectBurstEvent(sessState, event.EventOpenat, 3) {
		t.Fatalf("expected ignored runtime/tooling opens not to trigger burst_open")
	}

	sessState = SessionSnapshot{
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, Path: "/home/ubuntu/.profile", Time: now},
			{Type: event.EventOpenat, Path: "/workspace/project/package.json", Time: now.Add(200 * time.Millisecond)},
			{Type: event.EventOpenat, Path: "/workspace/project/package-lock.json", Time: now.Add(400 * time.Millisecond)},
		},
	}
	if detectBurstEvent(sessState, event.EventOpenat, 3) {
		t.Fatalf("expected ignored shell/bootstrap manifests not to trigger burst_open")
	}

	sessState = SessionSnapshot{
		RecentEvents: []ObservedEvent{
			{Type: event.EventOpenat, Path: "/tmp/a", Time: now},
			{Type: event.EventOpenat, Path: "/tmp/b", Time: now.Add(200 * time.Millisecond)},
			{Type: event.EventOpenat, Path: "/tmp/c", Time: now.Add(400 * time.Millisecond)},
		},
	}
	if !detectBurstEvent(sessState, event.EventOpenat, 3) {
		t.Fatalf("expected real burst of opens to trigger burst_open")
	}
}
