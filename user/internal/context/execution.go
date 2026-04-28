package context

// buildExecutionChainContext projects lineage and execution metadata into derived facts.
func buildExecutionChainContext(procState *ProcessState) ExecutionContext {
	heuristics := CurrentHeuristics()
	lineage := append([]LineageNode(nil), procState.Lineage...)
	if len(lineage) == 0 {
		lineage = []LineageNode{{
			PID:  procState.PID,
			PPID: procState.PPID,
			Comm: procState.Comm,
		}}
	}

	return ExecutionContext{
		Lineage:                 lineage,
		BinaryPath:              procState.ExecPath,
		UID:                     procState.UID,
		ChainDepth:              procState.LineageDepth,
		SuspiciousPathExec:      isSuspiciousPath(procState.ExecPath),
		DeepChain:               procState.LineageDepth >= heuristics.DeepChainThreshold,
		ShellInChain:            lineageHasCommand(lineage, nameSet(heuristics.ShellNames)),
		NetworkToolInChain:      lineageHasCommand(lineage, nameSet(heuristics.NetworkToolNames)),
		InterpreterInChain:      lineageHasCommand(lineage, nameSet(heuristics.InterpreterNames)),
		ContainerRuntimeInChain: lineageHasCommand(lineage, nameSet(heuristics.ContainerRuntimeNames)),
		MemfdOrDeletedExec:      isMemfdOrDeletedPath(procState.ExecPath),
	}
}
