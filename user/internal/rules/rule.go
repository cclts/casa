package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// FeatureValue is the flat rule-engine input format used by scoring.
type FeatureValue struct {
	Bool    bool
	Number  float64
	Present bool
}

// Config is the on-disk JSON schema for thresholds and weighted rules.
type Config struct {
	Analysis   AnalysisConfig `json:"analysis"`
	Thresholds Thresholds `json:"thresholds"`
	Rules      []Rule     `json:"rules"`
}

// AnalysisConfig holds non-rule knobs that still belong to the same policy source of truth.
type AnalysisConfig struct {
	LineageMaxDepth int `json:"lineage_max_depth"`
}

// Thresholds defines the cutoffs that map numeric score to a decision action.
type Thresholds struct {
	Log   int `json:"log"`
	Alert int `json:"alert"`
}

// Rule describes one weighted predicate over a single extracted feature.
type Rule struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Feature     string   `json:"feature"`
	Weight      int      `json:"weight"`
	Enabled     bool     `json:"enabled"`
	Match       string   `json:"match"`
	MinValue    *float64 `json:"min_value,omitempty"`
}

// TriggeredRule captures the exact rules that contributed to the final score.
type TriggeredRule struct {
	Name    string
	Feature string
	Weight  int
	Value   string
}

// Engine owns the currently active rule configuration and supports hot reloads.
type Engine struct {
	mu     sync.RWMutex
	path   string
	config Config
}

// NewEngine loads the initial rule configuration from disk.
func NewEngine(path string) (*Engine, error) {
	engine := &Engine{path: path}
	if err := engine.Reload(); err != nil {
		return nil, err
	}
	return engine, nil
}

// Reload swaps in a freshly parsed rule file.
func (e *Engine) Reload() error {
	cfg, err := LoadConfig(e.path)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.config = cfg
	e.mu.Unlock()

	return nil
}

// ConfigSnapshot returns a copy of the active configuration.
func (e *Engine) ConfigSnapshot() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return e.config
}

// Evaluate applies all enabled rules and returns the accumulated score and matches.
func (e *Engine) Evaluate(features map[string]FeatureValue) (int, []TriggeredRule, Thresholds) {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	score := 0
	triggered := make([]TriggeredRule, 0, len(cfg.Rules))

	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}

		feature, ok := features[rule.Feature]
		if !ok || !feature.Present {
			continue
		}

		if !matches(rule, feature) {
			continue
		}

		score += rule.Weight
		triggered = append(triggered, TriggeredRule{
			Name:    rule.Name,
			Feature: rule.Feature,
			Weight:  rule.Weight,
			Value:   renderValue(feature),
		})
	}

	return score, triggered, cfg.Thresholds
}

// LoadConfig parses and validates the JSON rule file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// Validate checks that thresholds and per-rule match settings are internally consistent.
func (c Config) Validate() error {
	if c.Analysis.LineageMaxDepth <= 0 {
		return fmt.Errorf("analysis.lineage_max_depth must be > 0")
	}
	if c.Thresholds.Log < 0 || c.Thresholds.Alert < 0 {
		return fmt.Errorf("thresholds must be non-negative")
	}
	if c.Thresholds.Alert < c.Thresholds.Log {
		return fmt.Errorf("alert threshold must be >= log threshold")
	}

	for i, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule[%d] missing name", i)
		}
		if rule.Feature == "" {
			return fmt.Errorf("rule[%d] missing feature", i)
		}
		if rule.Match == "" {
			c.Rules[i].Match = "bool_true"
		}
		switch rule.Match {
		case "bool_true", "number_gte":
		default:
			return fmt.Errorf("rule[%d] invalid match mode %q", i, rule.Match)
		}
		if rule.Match == "number_gte" && rule.MinValue == nil {
			return fmt.Errorf("rule[%d] number_gte requires min_value", i)
		}
	}

	return nil
}

// matches evaluates one feature against one rule predicate.
func matches(rule Rule, feature FeatureValue) bool {
	match := rule.Match
	if match == "" {
		match = "bool_true"
	}

	switch match {
	case "bool_true":
		return feature.Bool
	case "number_gte":
		return rule.MinValue != nil && feature.Number >= *rule.MinValue
	default:
		return false
	}
}

// renderValue stores a human-friendly copy of the matched feature value in audit output.
func renderValue(feature FeatureValue) string {
	if feature.Bool {
		return "true"
	}
	return fmt.Sprintf("%.0f", feature.Number)
}
