package decision

import (
	"sync"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/diag"
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
	Increment      int
	Action         Action
	Triggered      []rules.TriggeredRule
	LogThreshold   int
	AlertThreshold int
}

// Engine bridges feature extraction and the configurable rule engine.
type Engine struct {
	ruleEngine *rules.Engine
	mu         sync.Mutex
	sessions   map[uint32]*sessionState
}

type sessionState struct {
	triggeredRuleNames map[string]struct{}
	accumulatedScore   int
}

// NewEngine wraps a rule engine with decision thresholds and action mapping.
func NewEngine(ruleEngine *rules.Engine) *Engine {
	return &Engine{
		ruleEngine: ruleEngine,
		sessions:   make(map[uint32]*sessionState),
	}
}

// Evaluate scores a raw session snapshot and maps the numeric score to an action tier.
func (e *Engine) Evaluate(snapshot context.ContextSnapshot) Result {
	profile := Profile{
		SessionID: snapshot.SessionID,
		Features:  snapshot.FeatureMap(),
	}
	_, matched, threshold := e.ruleEngine.Evaluate(profile.Features)
	e.mu.Lock()
	state := e.getOrCreateSessionStateLocked(snapshot.SessionID)
	triggered := newlyTriggeredRules(matched, state.triggeredRuleNames)
	increment := scoreRules(triggered)
	score := state.accumulatedScore + increment

	action := ActionIgnore
	if len(triggered) > 0 {
		for _, item := range triggered {
			state.triggeredRuleNames[item.Name] = struct{}{}
		}
		state.accumulatedScore = score

		switch {
		case score >= threshold.Alert:
			action = ActionAlert
		case score >= threshold.Log:
			action = ActionLog
		}
	}
	e.mu.Unlock()

	if diag.Enabled() {
		diag.Logf("[DECISION DEBUG] session=%d matched=%v newly_triggered=%v increment=%d score=%d action=%s history=%v",
			snapshot.SessionID,
			ruleNames(matched),
			ruleNames(triggered),
			increment,
			score,
			action,
			snapshot.History,
		)
	}

	return Result{
		Profile:        profile,
		Score:          score,
		Increment:      increment,
		Action:         action,
		Triggered:      triggered,
		LogThreshold:   threshold.Log,
		AlertThreshold: threshold.Alert,
	}
}

func ruleNames(items []rules.TriggeredRule) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Name)
	}
	return out
}

func (e *Engine) getOrCreateSessionStateLocked(sessionID uint32) *sessionState {
	state, ok := e.sessions[sessionID]
	if ok {
		return state
	}
	state = &sessionState{
		triggeredRuleNames: make(map[string]struct{}),
	}
	e.sessions[sessionID] = state
	return state
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

func (e *Engine) CloseSession(sessionID uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.sessions, sessionID)
}

// CrossesAlertThreshold reports whether this result should be treated as alert-level.
func (r Result) CrossesAlertThreshold() bool {
	return len(r.Triggered) > 0 && r.Score >= r.AlertThreshold
}

func newlyTriggeredRules(matched []rules.TriggeredRule, seen map[string]struct{}) []rules.TriggeredRule {
	if len(matched) == 0 {
		return nil
	}

	out := make([]rules.TriggeredRule, 0, len(matched))
	for _, item := range matched {
		if _, ok := seen[item.Name]; ok {
			continue
		}
		out = append(out, item)
	}
	return out
}

func scoreRules(items []rules.TriggeredRule) int {
	total := 0
	for _, item := range items {
		total += item.Weight
	}
	return total
}
