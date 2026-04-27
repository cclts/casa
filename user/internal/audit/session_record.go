package audit

import (
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/rules"
)

const maxSessionEndpoints = 16

func updateSessionAggregate(session *sessionAggregate, result decision.Result) {
	if result.Score > session.MaxScore {
		session.MaxScore = result.Score
	}
	updateFinalDecision(session, result)
	mergeTriggeredRules(session, result.Triggered)
}

func snapshotSessionRecord(raw context.SessionSnapshot, session *sessionAggregate) SessionRecord {
	record := SessionRecord{
		CreatedAt:              formatTimestamp(raw.CreatedAt),
		UpdatedAt:              formatTimestamp(raw.UpdatedAt),
		IsClosed:               raw.IsClosed,
		EventCounts:            EventCounts{Execs: raw.Counts.Execs, Opens: raw.Counts.Opens, Connects: raw.Counts.Connects},
		UniqueConnectEndpoints: convertEndpoints(raw.UniqueConnectEndpoints),
		MaxLineageDepth:        raw.MaxLineageDepth,
		MaxScore:               session.MaxScore,
		AlertTriggered:         session.AlertTriggered,
		FinalDecision:          session.FinalDecision,
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
		TriggeredRules: append([]rules.TriggeredRule(nil), result.Triggered...),
	}
}

func updateFinalDecision(session *sessionAggregate, result decision.Result) {
	if actionPriority(result.Action) > actionPriority(session.FinalDecision.Action) ||
		(actionPriority(result.Action) == actionPriority(session.FinalDecision.Action) && result.Score >= session.FinalDecision.Score) {
		session.FinalDecision = buildDecisionRecord(result)
		return
	}

	if result.Score > session.FinalDecision.Score {
		session.FinalDecision.Score = result.Score
	}
}

func mergeTriggeredRules(session *sessionAggregate, triggered []rules.TriggeredRule) {
	for _, rule := range triggered {
		key := rule.Name
		if key == "" {
			key = rule.Expr
		}
		if _, ok := session.triggeredRuleIndex[key]; ok {
			continue
		}
		session.triggeredRuleIndex[key] = struct{}{}
		session.TriggeredRules = append(session.TriggeredRules, rule)
	}
}

func actionPriority(action decision.Action) int {
	switch action {
	case decision.ActionAlert:
		return 2
	case decision.ActionLog:
		return 1
	default:
		return 0
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
