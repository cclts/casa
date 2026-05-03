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
	if shouldIgnoreConfiguredConnect(e, tracker, providerClassifier) {
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

func shouldIgnoreConfiguredConnect(
	e event.Event,
	tracker *process.Tracker,
	providerClassifier *provider.Classifier,
) bool {
	return providerClassifier != nil && providerClassifier.ShouldIgnoreConfiguredConnect(e, tracker)
}

func ignoreReason(e event.Event) string {
	switch {
	case isMissingStructuredFields(e):
		return "missing_structured_fields"
	case isRuntimeLoaderNoise(e):
		return "runtime_loader_noise"
	case isRoutineSessionFileNoise(e):
		return "routine_session_file_noise"
	case isTransparentRoutineExec(e):
		return "transparent_routine_exec"
	case isIgnorableConnectNoise(e):
		return "ignorable_connect_noise"
	default:
		return "unknown"
	}
}
