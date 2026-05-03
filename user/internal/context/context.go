package context

import "time"

// ContextSnapshot is the in-memory session-level aggregate consumed by decision.
type ContextSnapshot struct {
	SessionID  uint32
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ClosedAt   time.Time
	Execution  ExecutionChainContext
	Capability CapabilityContext
	History    HistoricalContext
}

// ExecutionChainContext answers "where did this process come from?".
type ExecutionChainContext struct {
	SuspiciousPathExec      bool
	DeepChain               bool
	ShellInChain            bool
	NetworkToolInChain      bool
	InterpreterInChain      bool
	ContainerRuntimeInChain bool
	MemfdOrDeletedExec      bool
}

// CapabilityContext answers "what is this process allowed to do?".
type CapabilityContext struct {
	CapabilityUnknown bool
	DangerousCount    int
	HasDangerousCaps  bool
	SeccompDisabled   bool
}

// HistoricalContext answers "what has this session already done?".
type HistoricalContext struct {
	ConnectThenExec       bool
	SensitiveThenNetwork  bool
	SensitiveThenExecve   bool
	BurstOpen             bool
	BurstConnect          bool
	BurstExec             bool
	WriteThenExecSamePath bool
	OpenedDeletedPath     bool
}

// FeatureMap exposes the CEL-friendly view of the current derived aggregate.
func (s ContextSnapshot) FeatureMap() map[string]any {
	return map[string]any{
		"session_id": int64(s.SessionID),
		"execution": map[string]any{
			"suspicious_path_exec":       s.Execution.SuspiciousPathExec,
			"deep_chain":                 s.Execution.DeepChain,
			"shell_in_chain":             s.Execution.ShellInChain,
			"network_tool_in_chain":      s.Execution.NetworkToolInChain,
			"interpreter_in_chain":       s.Execution.InterpreterInChain,
			"container_runtime_in_chain": s.Execution.ContainerRuntimeInChain,
			"memfd_or_deleted_exec":      s.Execution.MemfdOrDeletedExec,
		},
		"capability": map[string]any{
			"has_dangerous_caps": s.Capability.HasDangerousCaps,
			"dangerous_count":    int64(s.Capability.DangerousCount),
			"seccomp_disabled":   s.Capability.SeccompDisabled,
		},
		"history": map[string]any{
			"connect_then_exec":         s.History.ConnectThenExec,
			"sensitive_then_network":    s.History.SensitiveThenNetwork,
			"sensitive_then_execve":     s.History.SensitiveThenExecve,
			"burst_open":                s.History.BurstOpen,
			"burst_connect":             s.History.BurstConnect,
			"burst_exec":                s.History.BurstExec,
			"write_then_exec_same_path": s.History.WriteThenExecSamePath,
			"opened_deleted_path":       s.History.OpenedDeletedPath,
		},
	}
}
