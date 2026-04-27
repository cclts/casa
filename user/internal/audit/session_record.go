package audit

import (
	"time"

	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/rules"
)

const maxSessionEndpoints = 16

func updateSessionAggregate(session *sessionAggregate, e event.Event, result decision.Result) {
	session.UpdatedAt = e.Time
	if result.Score > session.MaxScore {
		session.MaxScore = result.Score
	}
	updateFinalDecision(session, result)
	mergeTriggeredRules(session, result.Triggered)

	switch e.Type {
	case event.EventExecve:
		session.EventCounts.Execs++
	case event.EventOpenat:
		session.EventCounts.Opens++
	case event.EventConnect:
		session.EventCounts.Connects++
		endpoint := context.Endpoint{Addr: e.Addr, Port: e.Port}
		session.UniqueConnectEndpoints = appendUniqueEndpoint(session.UniqueConnectEndpoints, endpoint)
	}
}

func snapshotSessionRecord(session *sessionAggregate) SessionRecord {
	record := SessionRecord{
		CreatedAt:              formatTimestamp(session.CreatedAt),
		UpdatedAt:              formatTimestamp(session.UpdatedAt),
		IsClosed:               session.IsClosed,
		EventCounts:            session.EventCounts,
		UniqueConnectEndpoints: append([]context.Endpoint(nil), session.UniqueConnectEndpoints...),
		MaxScore:               session.MaxScore,
		AlertTriggered:         session.AlertTriggered,
		FinalDecision:          session.FinalDecision,
		TriggeredRules:         append([]rules.TriggeredRule(nil), session.TriggeredRules...),
	}
	if !session.ClosedAt.IsZero() {
		record.ClosedAt = formatTimestamp(session.ClosedAt)
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

func appendUniqueEndpoint(items []context.Endpoint, endpoint context.Endpoint) []context.Endpoint {
	for _, item := range items {
		if item == endpoint {
			return items
		}
	}

	items = append(items, endpoint)
	if len(items) <= maxSessionEndpoints {
		return items
	}
	return items[len(items)-maxSessionEndpoints:]
}

func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Format(time.RFC3339Nano)
}
