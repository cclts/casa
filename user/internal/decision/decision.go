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

// Evaluate scores a raw session snapshot and maps the numeric score to an action tier.
func (e *Engine) Evaluate(snapshot context.ContextSnapshot) Result {
	profile := Profile{
		SessionID: snapshot.SessionID,
		Features:  snapshot.FeatureMap(),
	}
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
