package decision

import (
	"github.com/cclts/care-go/user/internal/context"
	"github.com/cclts/care-go/user/internal/rules"
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
	Features  map[string]rules.FeatureValue
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
	features := map[string]rules.FeatureValue{
		"execution.suspicious_path_exec": boolFeature(ctx.Execution.SuspiciousPathExec),
		"execution.chain_depth":     numberFeature(float64(ctx.Execution.ChainDepth)),
		"execution.deep_chain":      boolFeature(ctx.Execution.DeepChain),
		"execution.shell_in_chain": boolFeature(ctx.Execution.ShellInChain),
		"execution.curl_wget_in_chain": boolFeature(ctx.Execution.CurlWgetInChain),
		"execution.interpreter_in_chain": boolFeature(ctx.Execution.InterpreterInChain),
		"execution.container_runtime_in_chain": boolFeature(ctx.Execution.ContainerRuntimeInChain),
		"execution.memfd_or_deleted_exec": boolFeature(ctx.Execution.MemfdOrDeletedExec),
		"capability.has_dangerous_caps":      boolFeature(ctx.Capability.HasDangerousCaps),
		"capability.dangerous_count": numberFeature(float64(len(ctx.Capability.DangerousCaps))),
		"capability.seccomp_disabled": boolFeature(!ctx.Capability.CapabilityUnknown && ctx.Capability.SeccompDisabled),
		"history.connect_then_exec":   boolFeature(ctx.History.ConnectThenExec),
		"history.sensitive_then_network": boolFeature(ctx.History.SensitiveThenNetwork),
		"history.sensitive_then_execve": boolFeature(ctx.History.SensitiveThenExecve),
		"history.burst_connect": boolFeature(ctx.History.BurstConnect),
		"history.burst_exec": boolFeature(ctx.History.BurstExec),
		"history.unique_open_path_count": numberFeature(float64(ctx.History.UniqueOpenPathCount)),
		"file.write_then_exec_same_path": boolFeature(ctx.File.WriteThenExecSamePath),
		"file.opened_deleted_path": boolFeature(ctx.File.OpenedDeletedPath),
		"history.exec_count":             numberFeature(float64(ctx.History.ExecCount)),
		"history.open_count":             numberFeature(float64(ctx.History.OpenCount)),
		"history.connect_count":          numberFeature(float64(ctx.History.ConnectCount)),
	}

	return Profile{
		SessionID: ctx.SessionID,
		TargetPID: ctx.TargetPID,
		Features:  features,
	}
}

// boolFeature wraps a boolean observation in the shared rule-engine feature format.
func boolFeature(v bool) rules.FeatureValue {
	return rules.FeatureValue{
		Bool:    v,
		Number:  0,
		Present: true,
	}
}

// numberFeature wraps a numeric observation in the shared rule-engine feature format.
func numberFeature(v float64) rules.FeatureValue {
	return rules.FeatureValue{
		Bool:    false,
		Number:  v,
		Present: true,
	}
}
