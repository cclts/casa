package context

// BuildContext materializes a context snapshot for one process inside a session.
func BuildContext(state *SessionState, targetPID uint32) Context {
	ctx := Context{
		SessionID: state.ID,
		TargetPID: targetPID,
	}

	procState := state.Processes[targetPID]
	if procState == nil {
		return ctx
	}

	ctx.Execution = buildExecutionChainContext(procState)
	ctx.Capability = buildCapabilityContext(procState)
	ctx.History = buildHistoricalContext(state, targetPID)
	ctx.File = buildFileContext(procState)

	return ctx
}
