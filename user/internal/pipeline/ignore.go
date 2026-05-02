package pipeline

import (
	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
	"github.com/cclts/casa/user/internal/provider"
)

func shouldIgnoreSecurityPipelineEvent(
	e event.Event,
	sessionID process.SessionID,
	contextManager *context.Manager,
	tracker *process.Tracker,
	providerClassifier *provider.Classifier,
) bool {
	if shouldIgnoreProviderConnect(e, tracker, providerClassifier) {
		return true
	}

	if e.Type != event.EventExit && !ShouldIngestIntoContext(e) {
		contextManager.ObserveIgnored(sessionID, e)
		return true
	}

	if e.Type == event.EventExit && contextManager.ObserveIgnored(sessionID, e) {
		return true
	}

	return false
}

func shouldIgnoreProviderConnect(
	e event.Event,
	tracker *process.Tracker,
	providerClassifier *provider.Classifier,
) bool {
	return providerClassifier != nil && providerClassifier.ShouldIgnoreProviderConnect(e, tracker)
}
