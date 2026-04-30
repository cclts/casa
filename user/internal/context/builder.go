package context

// BuildContext materializes a session-scoped context snapshot.
func BuildContext(state *SessionState) Context {
	ctx := Context{
		SessionID: state.ID,
	}

	procState := state.Processes[state.LastExecPID]
	if procState == nil {
		ctx.History = buildHistoricalContext(state)
		ctx.File = buildFileContext(state)
		return ctx
	}

	ctx.Execution = buildExecutionChainContext(state, procState)
	ctx.Capability = buildCapabilityContext(procState)
	ctx.History = buildHistoricalContext(state)
	ctx.File = buildFileContext(state)

	return ctx
}
