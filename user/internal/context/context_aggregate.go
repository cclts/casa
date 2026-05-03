package context

import "sort"

func syncContextTimestamps(ctxState *ContextSnapshot, session *SessionState) {
	if ctxState == nil || session == nil {
		return
	}
	ctxState.UpdatedAt = session.UpdatedAt
	if !session.ClosedAt.IsZero() {
		ctxState.ClosedAt = session.ClosedAt
	}
}

func updateExecutionAggregate(dst *ExecutionChainContext, src ExecutionChainContext) {
	dst.SuspiciousPathExec = dst.SuspiciousPathExec || src.SuspiciousPathExec
	dst.DeepChain = dst.DeepChain || src.DeepChain
	dst.ShellInChain = dst.ShellInChain || src.ShellInChain
	dst.NetworkToolInChain = dst.NetworkToolInChain || src.NetworkToolInChain
	dst.InterpreterInChain = dst.InterpreterInChain || src.InterpreterInChain
	dst.ContainerRuntimeInChain = dst.ContainerRuntimeInChain || src.ContainerRuntimeInChain
	dst.MemfdOrDeletedExec = dst.MemfdOrDeletedExec || src.MemfdOrDeletedExec
}

func updateCapabilityAggregate(dst *CapabilityContext, src CapabilityContext) {
	dst.CapabilityUnknown = dst.CapabilityUnknown || src.CapabilityUnknown
	if src.DangerousCount > dst.DangerousCount {
		dst.DangerousCount = src.DangerousCount
	}
	dst.HasDangerousCaps = dst.HasDangerousCaps || src.HasDangerousCaps
	dst.SeccompDisabled = dst.SeccompDisabled || src.SeccompDisabled
}

func cloneContextSnapshot(src *ContextSnapshot) ContextSnapshot {
	if src == nil {
		return ContextSnapshot{}
	}
	return *src
}

func rebuildContextAggregates(ctxState *ContextSnapshot, session *SessionState) {
	if ctxState == nil || session == nil {
		return
	}
	ctxState.Execution = rebuildExecutionAggregate(session)
	ctxState.Capability = rebuildCapabilityAggregate(session)
}

func rebuildExecutionAggregate(session *SessionState) ExecutionChainContext {
	if session == nil {
		return ExecutionChainContext{}
	}

	var agg ExecutionChainContext
	for _, pid := range sortedAggregateProcessIDs(session) {
		procState := session.Processes[pid]
		if procState == nil {
			continue
		}
		updateExecutionAggregate(&agg, BuildExecutionChainContext(procState))
	}
	return agg
}

func rebuildCapabilityAggregate(session *SessionState) CapabilityContext {
	if session == nil {
		return CapabilityContext{}
	}

	var agg CapabilityContext
	for _, pid := range sortedAggregateProcessIDs(session) {
		procState := session.Processes[pid]
		if procState == nil {
			continue
		}
		updateCapabilityAggregate(&agg, BuildCapabilityContext(procState))
	}
	return agg
}

func sortedAggregateProcessIDs(session *SessionState) []uint32 {
	pids := make([]uint32, 0, len(session.Processes))
	for pid, procState := range session.Processes {
		if procState == nil {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}
