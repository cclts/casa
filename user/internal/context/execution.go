package context

// BuildExecutionChainContext projects one process's execution metadata into derived facts.
func BuildExecutionChainContext(procState *ProcessState) ExecutionChainContext {
	heuristics := CurrentHeuristics()

	return ExecutionChainContext{
		SuspiciousPathExec:      isSuspiciousPath(procState.ExecPath),
		DeepChain:               procState.LineageDepth >= heuristics.DeepChainThreshold,
		ShellInChain:            lineageHasCommand(procState, nameSet(heuristics.ShellNames)),
		NetworkToolInChain:      lineageHasCommand(procState, nameSet(heuristics.NetworkToolNames)),
		InterpreterInChain:      lineageHasCommand(procState, nameSet(heuristics.InterpreterNames)),
		ContainerRuntimeInChain: lineageHasCommand(procState, nameSet(heuristics.ContainerRuntimeNames)),
		MemfdOrDeletedExec:      isMemfdOrDeletedPath(procState.ExecPath),
	}
}
