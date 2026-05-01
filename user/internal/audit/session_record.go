package audit

import (
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/rules"
)

func snapshotSessionRecord(raw context.SessionSnapshot) SessionRecord {
	record := SessionRecord{
		CreatedAt:    formatTimestamp(raw.CreatedAt),
		UpdatedAt:    formatTimestamp(raw.UpdatedAt),
		RecentEvents: convertRecentEvents(raw.RecentEvents),
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

func convertRecentEvents(items []context.ObservedEvent) []RecentEventRecord {
	if len(items) == 0 {
		return nil
	}

	out := make([]RecentEventRecord, 0, len(items))
	for _, item := range items {
		record := RecentEventRecord{
			Timestamp: formatTimestamp(item.Time),
			Type:      item.Type.String(),
			PID:       item.PID,
		}
		if item.Path != "" {
			record.Path = stringPtr(item.Path)
		}
		if item.Flags != 0 {
			record.Flags = uint32Ptr(item.Flags)
		}
		if item.Mode != 0 {
			record.Mode = uint32Ptr(item.Mode)
		}
		if item.Addr != "" {
			record.Addr = stringPtr(item.Addr)
		}
		if item.Port != 0 {
			record.Port = uint16Ptr(item.Port)
		}
		out = append(out, record)
	}

	return out
}
