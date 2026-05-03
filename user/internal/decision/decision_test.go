package decision

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/rules"
)

func TestEvaluateOnlyScoresNewlyTriggeredRulesPerSession(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "rules.json")
	data := []byte(`{
  "analysis": {
    "lineage_max_depth": 8
  },
  "thresholds": {
    "log": 2,
    "alert": 10
  },
  "rules": [
    {
      "name": "opened_deleted_path",
      "description": "test rule",
      "expr": "history.opened_deleted_path",
      "weight": 6,
      "enabled": true
    }
  ]
}`)
	if err := os.WriteFile(rulePath, data, 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}

	ruleEngine, err := rules.NewEngine(rulePath)
	if err != nil {
		t.Fatalf("new rules engine: %v", err)
	}
	engine := NewEngine(ruleEngine)

	first := engine.Evaluate(context.ContextSnapshot{
		SessionID: 1,
		History: context.HistoricalContext{
			OpenedDeletedPath: true,
		},
	})
	if len(first.Triggered) != 1 {
		t.Fatalf("expected one newly triggered rule, got %d", len(first.Triggered))
	}
	if first.Increment != 6 || first.Score != 6 {
		t.Fatalf("expected first score increment to be 6, got increment=%d total=%d", first.Increment, first.Score)
	}

	second := engine.Evaluate(context.ContextSnapshot{
		SessionID: 1,
		History: context.HistoricalContext{
			OpenedDeletedPath: true,
		},
	})
	if len(second.Triggered) != 0 {
		t.Fatalf("expected repeated rule not to trigger again, got %d", len(second.Triggered))
	}
	if second.Increment != 0 || second.Score != 6 {
		t.Fatalf("expected no extra score on repeat, got increment=%d total=%d", second.Increment, second.Score)
	}
	if second.Action != ActionIgnore {
		t.Fatalf("expected repeat event without new rules to stay IGNORE, got %s", second.Action)
	}
}
