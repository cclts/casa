package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/google/cel-go/cel"
)

// Config is the on-disk JSON schema for thresholds and weighted rules.
type Config struct {
	Analysis   AnalysisConfig `json:"analysis"`
	Thresholds Thresholds     `json:"thresholds"`
	Rules      []Rule         `json:"rules"`
}

// AnalysisConfig holds non-rule knobs that still belong to the same policy source of truth.
type AnalysisConfig struct {
	LineageMaxDepth            int      `json:"lineage_max_depth"`
	RecentEventLimit           int      `json:"recent_event_limit,omitempty"`
	MaxPerProcessArtifacts     int      `json:"max_per_process_artifacts,omitempty"`
	DeepChainThreshold         int      `json:"deep_chain_threshold,omitempty"`
	BurstOpenThreshold         int      `json:"burst_open_threshold,omitempty"`
	BurstConnectThreshold      int      `json:"burst_connect_threshold,omitempty"`
	BurstExecThreshold         int      `json:"burst_exec_threshold,omitempty"`
	BurstWindowSeconds         int      `json:"burst_window_seconds,omitempty"`
	SensitiveHistoryWindowSecs int      `json:"sensitive_history_window_seconds,omitempty"`
	SuspiciousPathPatterns     []string `json:"suspicious_path_patterns,omitempty"`
	SensitivePathPrefixes      []string `json:"sensitive_path_prefixes,omitempty"`
	SensitivePathPatterns      []string `json:"sensitive_path_patterns,omitempty"`
	ShellNames                 []string `json:"shell_names,omitempty"`
	NetworkToolNames           []string `json:"network_tool_names,omitempty"`
	InterpreterNames           []string `json:"interpreter_names,omitempty"`
	ContainerRuntimeNames      []string `json:"container_runtime_names,omitempty"`
	DangerousCapabilityNames   []string `json:"dangerous_capability_names,omitempty"`
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
	Expr        string   `json:"expr"`
	Feature     string   `json:"feature"`
	Weight      int      `json:"weight"`
	Enabled     bool     `json:"enabled"`
	Match       string   `json:"match"`
	MinValue    *float64 `json:"min_value,omitempty"`

	program cel.Program `json:"-"`
}

// TriggeredRule captures the exact rules that contributed to the final score.
type TriggeredRule struct {
	Name   string `json:"name"`
	Expr   string `json:"expr,omitempty"`
	Weight int    `json:"weight"`
}

// Engine owns the currently active rule configuration and supports hot reloads.
type Engine struct {
	mu     sync.RWMutex
	path   string
	config Config
	env    *cel.Env
}

// NewEngine loads the initial rule configuration from disk.
func NewEngine(path string) (*Engine, error) {
	env, err := cel.NewEnv(
		cel.Variable("execution", cel.DynType),
		cel.Variable("capability", cel.DynType),
		cel.Variable("history", cel.DynType),
		cel.Variable("session_id", cel.IntType),
	)
	if err != nil {
		return nil, err
	}

	engine := &Engine{
		path: path,
		env:  env,
	}
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

	for i := range cfg.Rules {
		if !cfg.Rules[i].Enabled {
			continue
		}

		ast, issues := e.env.Compile(cfg.Rules[i].Expr)
		if issues != nil && issues.Err() != nil {
			return fmt.Errorf("compile rule %q: %w", cfg.Rules[i].Name, issues.Err())
		}

		program, err := e.env.Program(ast)
		if err != nil {
			return fmt.Errorf("program rule %q: %w", cfg.Rules[i].Name, err)
		}

		cfg.Rules[i].program = program
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
func (e *Engine) Evaluate(features map[string]any) (int, []TriggeredRule, Thresholds) {
	e.mu.RLock()
	cfg := e.config
	e.mu.RUnlock()

	score := 0
	triggered := make([]TriggeredRule, 0, len(cfg.Rules))

	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}

		out, _, err := rule.program.Eval(features)
		if err != nil {
			continue
		}

		matched, ok := out.Value().(bool)
		if !ok || !matched {
			continue
		}

		score += rule.Weight
		triggered = append(triggered, TriggeredRule{
			Name:   rule.Name,
			Expr:   rule.Expr,
			Weight: rule.Weight,
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
func (c *Config) Validate() error {
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
		if rule.Expr == "" {
			if rule.Feature == "" {
				return fmt.Errorf("rule[%d] missing expr", i)
			}
			switch rule.Match {
			case "", "bool_true":
				c.Rules[i].Expr = rule.Feature
			case "number_gte":
				if rule.MinValue == nil {
					return fmt.Errorf("rule[%d] number_gte requires min_value", i)
				}
				c.Rules[i].Expr = fmt.Sprintf("%s >= %v", rule.Feature, *rule.MinValue)
			default:
				return fmt.Errorf("rule[%d] invalid legacy match mode %q", i, rule.Match)
			}
		}
	}

	return nil
}
