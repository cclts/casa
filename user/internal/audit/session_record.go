package audit

import (
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/rules"
)

const maxSessionEndpoints = 16

func snapshotSessionRecord(raw context.SessionSnapshot) SessionRecord {
	record := SessionRecord{
		CreatedAt:              formatTimestamp(raw.CreatedAt),
		UpdatedAt:              formatTimestamp(raw.UpdatedAt),
		IsClosed:               raw.IsClosed,
		EventCounts:            EventCounts{Execs: raw.Counts.Execs, Opens: raw.Counts.Opens, Connects: raw.Counts.Connects},
		UniqueConnectEndpoints: convertEndpoints(raw.UniqueConnectEndpoints),
		MaxLineageDepth:        raw.MaxLineageDepth,
	}
	if !raw.ClosedAt.IsZero() {
		record.ClosedAt = formatTimestamp(raw.ClosedAt)
	}
	return record
}

func buildDecisionRecord(result decision.Result) DecisionRecord {
	return DecisionRecord{
		Action:         result.Action,
		Score:          result.Score,
		LogThreshold:   result.LogThreshold,
		AlertThreshold: result.AlertThreshold,
		TriggeredRules: convertTriggeredRules(result.Triggered),
	}
}

func convertEndpoints(items []context.Endpoint) []Endpoint {
	if len(items) == 0 {
		return nil
	}
	if len(items) > maxSessionEndpoints {
		items = items[len(items)-maxSessionEndpoints:]
	}

	out := make([]Endpoint, 0, len(items))
	for _, item := range items {
		out = append(out, Endpoint{
			Addr: item.Addr,
			Port: item.Port,
		})
	}
	return out
}

func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Format(time.RFC3339Nano)
}

func convertTriggeredRules(items []rules.TriggeredRule) []TriggeredRuleRecord {
	if len(items) == 0 {
		return nil
	}

	out := make([]TriggeredRuleRecord, 0, len(items))
	for _, item := range items {
		out = append(out, TriggeredRuleRecord{
			Name:   item.Name,
			Expr:   item.Expr,
			Weight: item.Weight,
		})
	}
	return out
}
