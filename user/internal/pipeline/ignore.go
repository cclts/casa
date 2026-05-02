package pipeline

import (
	"log"

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
		log.Printf("[PIPELINE IGNORE] type=%s pid=%d ppid=%d reason=provider_connect", e.Type.String(), e.PID, e.PPID)
		return true
	}

	if e.Type != event.EventExit && !ShouldIngestIntoContext(e) {
		contextManager.ObserveIgnored(sessionID, e)
		log.Printf("[PIPELINE IGNORE] type=%s pid=%d ppid=%d reason=%s", e.Type.String(), e.PID, e.PPID, ignoreReason(e))
		return true
	}

	if e.Type == event.EventExit && contextManager.ObserveIgnored(sessionID, e) {
		log.Printf("[PIPELINE IGNORE] type=%s pid=%d ppid=%d reason=normalized_exit", e.Type.String(), e.PID, e.PPID)
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
