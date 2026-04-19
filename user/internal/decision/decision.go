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
	profile := BuildProfile(ctx)
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

// Reload refreshes the backing rule configuration without restarting the process.
func (e *Engine) Reload() error {
	return e.ruleEngine.Reload()
}

// BuildProfile converts rich context into a flat feature map that rules can score.
func BuildProfile(ctx context.Context) Profile {
	features := map[string]rules.FeatureValue{
		"execution.suspicious_path": boolFeature(ctx.Execution.SuspiciousPath),
		"execution.chain_depth":     numberFeature(float64(ctx.Execution.ChainDepth)),
		"execution.deep_chain":      boolFeature(ctx.Execution.ChainDepth >= 4),
		"capability.dangerous":      boolFeature(ctx.Capability.HasDangerousCaps),
		"capability.dangerous_count": numberFeature(float64(len(ctx.Capability.DangerousCaps))),
		"capability.seccomp_disabled": boolFeature(!ctx.Capability.CapabilityUnknown && !ctx.Capability.SeccompEnabled),
		"history.connect_then_exec":   boolFeature(ctx.History.ConnectThenExec),
		"history.sensitive_then_network": boolFeature(ctx.History.SensitiveFileThenNet),
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
