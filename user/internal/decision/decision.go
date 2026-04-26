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
	TargetPID uint32
	Features  map[string]any
}

// Result is the final decision payload emitted after risk evaluation.
type Result struct {
	Profile       Profile
	Score         int
	Action        Action
	Triggered     []rules.TriggeredRule
	LogThreshold  int
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

// Reload refreshes the backing rule configuration without restarting the process.
func (e *Engine) Reload() error {
	return e.ruleEngine.Reload()
}

// BuildProfile converts rich context into a flat feature map that rules can score.
func BuildProfile(ctx context.Context, _ int) Profile {
	features := map[string]any{
		"session_id": int64(ctx.SessionID),
		"target_pid": int64(ctx.TargetPID),
		"execution": map[string]any{
			"suspicious_path_exec":      ctx.Execution.SuspiciousPathExec,
			"chain_depth":               int64(ctx.Execution.ChainDepth),
			"deep_chain":                ctx.Execution.DeepChain,
			"shell_in_chain":            ctx.Execution.ShellInChain,
			"curl_wget_in_chain":        ctx.Execution.CurlWgetInChain,
			"interpreter_in_chain":      ctx.Execution.InterpreterInChain,
			"container_runtime_in_chain": ctx.Execution.ContainerRuntimeInChain,
			"memfd_or_deleted_exec":     ctx.Execution.MemfdOrDeletedExec,
		},
		"capability": map[string]any{
			"has_dangerous_caps": ctx.Capability.HasDangerousCaps,
			"dangerous_count":    int64(len(ctx.Capability.DangerousCaps)),
			"seccomp_disabled":   !ctx.Capability.CapabilityUnknown && ctx.Capability.SeccompDisabled,
		},
		"history": map[string]any{
			"connect_then_exec":     ctx.History.ConnectThenExec,
			"sensitive_then_network": ctx.History.SensitiveThenNetwork,
			"sensitive_then_execve": ctx.History.SensitiveThenExecve,
			"burst_connect":         ctx.History.BurstConnect,
			"burst_exec":            ctx.History.BurstExec,
			"unique_open_path_count": int64(ctx.History.UniqueOpenPathCount),
			"exec_count":            int64(ctx.History.ExecCount),
			"open_count":            int64(ctx.History.OpenCount),
			"connect_count":         int64(ctx.History.ConnectCount),
		},
		"file": map[string]any{
			"write_then_exec_same_path": ctx.File.WriteThenExecSamePath,
			"opened_deleted_path":       ctx.File.OpenedDeletedPath,
		},
	}

	return Profile{
		SessionID: ctx.SessionID,
		TargetPID: ctx.TargetPID,
		Features:  features,
	}
}
