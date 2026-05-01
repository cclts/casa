package context

import (
	"testing"

	"github.com/cclts/casa/user/internal/process"
)

func TestBuildCapabilityContextUsesDangerousCapabilityHeuristic(t *testing.T) {
	original := CurrentHeuristics()
	ConfigureHeuristics(Heuristics{
		RecentEventLimit:         original.RecentEventLimit,
		MaxPerProcessArtifacts:   original.MaxPerProcessArtifacts,
		DeepChainThreshold:       original.DeepChainThreshold,
		BurstOpenThreshold:       original.BurstOpenThreshold,
		BurstConnectThreshold:    original.BurstConnectThreshold,
		BurstExecThreshold:       original.BurstExecThreshold,
		BurstWindow:              original.BurstWindow,
		SensitiveHistoryWindow:   original.SensitiveHistoryWindow,
		SuspiciousPathPatterns:   original.SuspiciousPathPatterns,
		SensitivePathPrefixes:    original.SensitivePathPrefixes,
		SensitivePathPatterns:    original.SensitivePathPatterns,
		ShellNames:               original.ShellNames,
		NetworkToolNames:         original.NetworkToolNames,
		InterpreterNames:         original.InterpreterNames,
		ContainerRuntimeNames:    original.ContainerRuntimeNames,
		DangerousCapabilityNames: []string{"cap_net_raw"},
	})
	defer ConfigureHeuristics(original)

	procState := &ProcessState{
		Security: &process.SecuritySnapshot{
			Available:   true,
			CapEffMask:  1 << 13,
			SeccompMode: 2,
		},
	}

	ctx := BuildCapabilityContext(procState)
	if !ctx.HasDangerousCaps {
		t.Fatalf("expected configured dangerous capability to be detected")
	}
	if ctx.DangerousCount != 1 {
		t.Fatalf("expected dangerous count 1, got %d", ctx.DangerousCount)
	}
}

func TestBuildCapabilityContextIgnoresUnconfiguredCapability(t *testing.T) {
	original := CurrentHeuristics()
	ConfigureHeuristics(Heuristics{
		RecentEventLimit:         original.RecentEventLimit,
		MaxPerProcessArtifacts:   original.MaxPerProcessArtifacts,
		DeepChainThreshold:       original.DeepChainThreshold,
		BurstOpenThreshold:       original.BurstOpenThreshold,
		BurstConnectThreshold:    original.BurstConnectThreshold,
		BurstExecThreshold:       original.BurstExecThreshold,
		BurstWindow:              original.BurstWindow,
		SensitiveHistoryWindow:   original.SensitiveHistoryWindow,
		SuspiciousPathPatterns:   original.SuspiciousPathPatterns,
		SensitivePathPrefixes:    original.SensitivePathPrefixes,
		SensitivePathPatterns:    original.SensitivePathPatterns,
		ShellNames:               original.ShellNames,
		NetworkToolNames:         original.NetworkToolNames,
		InterpreterNames:         original.InterpreterNames,
		ContainerRuntimeNames:    original.ContainerRuntimeNames,
		DangerousCapabilityNames: []string{"CAP_SYS_PTRACE"},
	})
	defer ConfigureHeuristics(original)

	procState := &ProcessState{
		Security: &process.SecuritySnapshot{
			Available:   true,
			CapEffMask:  1 << 13,
			SeccompMode: 2,
		},
	}

	ctx := BuildCapabilityContext(procState)
	if ctx.HasDangerousCaps {
		t.Fatalf("expected unconfigured capability not to be treated as dangerous")
	}
	if ctx.DangerousCount != 0 {
		t.Fatalf("expected dangerous count 0, got %d", ctx.DangerousCount)
	}
}
