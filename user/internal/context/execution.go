package context

// buildExecutionChainContext projects lineage and execution metadata into derived facts.
func buildExecutionChainContext(procState *ProcessState) ExecutionContext {
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
		DeepChain:               procState.LineageDepth >= deepChainThreshold,
		ShellInChain:            lineageHasCommand(lineage, shellNames),
		NetworkToolInChain:      lineageHasCommand(lineage, networkToolNames),
		InterpreterInChain:      lineageHasCommand(lineage, interpreterNames),
		ContainerRuntimeInChain: lineageHasCommand(lineage, containerRuntimeNames),
		MemfdOrDeletedExec:      isMemfdOrDeletedPath(procState.ExecPath),
	}
}
