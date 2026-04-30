package decision

import (
	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/rules"
)

// Action is the coarse-grained outcome of risk evaluation.
type Action string

const (
	ActionIgnore Action = "IGNORE"
	ActionLog    Action = "LOG"
	ActionAlert  Action = "ALERT"
)

// Profile is the flattened feature set extracted from a richer context snapshot.
type Profile struct {
	SessionID uint32
	Features  map[string]any
}

// Result is the final decision payload emitted after risk evaluation.
type Result struct {
	Profile        Profile
	Score          int
	Action         Action
	Triggered      []rules.TriggeredRule
	LogThreshold   int
	AlertThreshold int
}

// Engine bridges feature extraction and the configurable rule engine.
type Engine struct {
	ruleEngine *rules.Engine
}

// NewEngine wraps a rule engine with decision thresholds and action mapping.
func NewEngine(ruleEngine *rules.Engine) *Engine {
	return &Engine{
		ruleEngine: ruleEngine,
	}
}

// Evaluate scores a context snapshot and maps the numeric score to an action tier.
func (e *Engine) Evaluate(ctx context.Context) Result {
	cfg := e.ruleEngine.ConfigSnapshot()
	profile := BuildProfile(ctx, cfg.Analysis.LineageMaxDepth)
	score, triggered, threshold := e.ruleEngine.Evaluate(profile.Features)

	action := ActionIgnore
	switch {
	case score >= threshold.Alert:
		action = ActionAlert
	case score >= threshold.Log:
		action = ActionLog
	}

	return Result{
		Profile:        profile,
		Score:          score,
		Action:         action,
		Triggered:      triggered,
		LogThreshold:   threshold.Log,
		AlertThreshold: threshold.Alert,
	}
}

// LineageMaxDepth exposes the configured lineage depth limit used throughout the pipeline.
func (e *Engine) LineageMaxDepth() int {
	return e.ruleEngine.ConfigSnapshot().Analysis.LineageMaxDepth
}

// AnalysisConfig exposes the currently active non-rule analysis knobs.
func (e *Engine) AnalysisConfig() rules.AnalysisConfig {
	return e.ruleEngine.ConfigSnapshot().Analysis
}

// Reload refreshes the backing rule configuration without restarting the process.
func (e *Engine) Reload() error {
	return e.ruleEngine.Reload()
}

// CrossesAlertThreshold reports whether this result should be treated as alert-level.
func (r Result) CrossesAlertThreshold() bool {
	return r.Score >= r.AlertThreshold
}

// BuildProfile converts rich context into a flat feature map that rules can score.
func BuildProfile(ctx context.Context, _ int) Profile {
	execution := aggregateExecutionFeatures(ctx)
	capability := aggregateCapabilityFeatures(ctx)

	features := map[string]any{
		"session_id": int64(ctx.SessionID),
		"execution": map[string]any{
			"suspicious_path_exec":       execution.SuspiciousPathExec,
			"chain_depth":                int64(execution.ChainDepth),
			"deep_chain":                 execution.DeepChain,
			"shell_in_chain":             execution.ShellInChain,
			"network_tool_in_chain":      execution.NetworkToolInChain,
			"interpreter_in_chain":       execution.InterpreterInChain,
			"container_runtime_in_chain": execution.ContainerRuntimeInChain,
			"memfd_or_deleted_exec":      execution.MemfdOrDeletedExec,
		},
		"capability": map[string]any{
			"has_dangerous_caps": capability.HasDangerousCaps,
			"dangerous_count":    int64(capability.DangerousCount),
			"seccomp_disabled":   capability.SeccompDisabled,
		},
		"history": map[string]any{
			"connect_then_exec":         ctx.History.ConnectThenExec,
			"sensitive_then_network":    ctx.History.SensitiveThenNetwork,
			"sensitive_then_execve":     ctx.History.SensitiveThenExecve,
			"burst_connect":             ctx.History.BurstConnect,
			"burst_exec":                ctx.History.BurstExec,
			"unique_open_path_count":    int64(ctx.History.UniqueOpenPathCount),
			"exec_count":                int64(ctx.History.ExecCount),
			"open_count":                int64(ctx.History.OpenCount),
			"connect_count":             int64(ctx.History.ConnectCount),
			"write_then_exec_same_path": ctx.History.WriteThenExecSamePath,
			"opened_deleted_path":       ctx.History.OpenedDeletedPath,
		},
	}

	return Profile{
		SessionID: ctx.SessionID,
		Features:  features,
	}
}

type aggregatedExecutionFeatures struct {
	ChainDepth              int
	SuspiciousPathExec      bool
	DeepChain               bool
	ShellInChain            bool
	NetworkToolInChain      bool
	InterpreterInChain      bool
	ContainerRuntimeInChain bool
	MemfdOrDeletedExec      bool
}

type aggregatedCapabilityFeatures struct {
	DangerousCount   int
	HasDangerousCaps bool
	SeccompDisabled  bool
}

func aggregateExecutionFeatures(ctx context.Context) aggregatedExecutionFeatures {
	var out aggregatedExecutionFeatures
	for _, item := range ctx.ExecutionChains {
		if item.ChainDepth > out.ChainDepth {
			out.ChainDepth = item.ChainDepth
		}
		out.SuspiciousPathExec = out.SuspiciousPathExec || item.SuspiciousPathExec
		out.DeepChain = out.DeepChain || item.DeepChain
		out.ShellInChain = out.ShellInChain || item.ShellInChain
		out.NetworkToolInChain = out.NetworkToolInChain || item.NetworkToolInChain
		out.InterpreterInChain = out.InterpreterInChain || item.InterpreterInChain
		out.ContainerRuntimeInChain = out.ContainerRuntimeInChain || item.ContainerRuntimeInChain
		out.MemfdOrDeletedExec = out.MemfdOrDeletedExec || item.MemfdOrDeletedExec
	}
	return out
}

func aggregateCapabilityFeatures(ctx context.Context) aggregatedCapabilityFeatures {
	var out aggregatedCapabilityFeatures
	for _, item := range ctx.Capabilities {
		if len(item.DangerousCaps) > out.DangerousCount {
			out.DangerousCount = len(item.DangerousCaps)
		}
		out.HasDangerousCaps = out.HasDangerousCaps || item.HasDangerousCaps
		if !item.CapabilityUnknown {
			out.SeccompDisabled = out.SeccompDisabled || item.SeccompDisabled
		}
	}
	return out
}
