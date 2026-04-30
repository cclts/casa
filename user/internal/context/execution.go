package context

// buildExecutionChainContext projects lineage and execution metadata into derived facts.
func buildExecutionChainContext(state *SessionState, procState *ProcessState) ExecutionChainContext {
	heuristics := CurrentHeuristics()
	lineage := append([]LineageNode(nil), procState.Lineage...)
	if len(lineage) == 0 {
		lineage = []LineageNode{{
			PID:  procState.PID,
			PPID: procState.PPID,
		}}
	}

	return ExecutionChainContext{
		PID:                     procState.PID,
		PPID:                    procState.PPID,
		Lineage:                 lineage,
		BinaryPath:              procState.ExecPath,
		UID:                     procState.UID,
		ChainDepth:              procState.LineageDepth,
		SuspiciousPathExec:      isSuspiciousPath(procState.ExecPath),
		DeepChain:               procState.LineageDepth >= heuristics.DeepChainThreshold,
		ShellInChain:            lineageHasCommand(state, lineage, nameSet(heuristics.ShellNames)),
		NetworkToolInChain:      lineageHasCommand(state, lineage, nameSet(heuristics.NetworkToolNames)),
		InterpreterInChain:      lineageHasCommand(state, lineage, nameSet(heuristics.InterpreterNames)),
		ContainerRuntimeInChain: lineageHasCommand(state, lineage, nameSet(heuristics.ContainerRuntimeNames)),
		MemfdOrDeletedExec:      isMemfdOrDeletedPath(procState.ExecPath),
	}
}
