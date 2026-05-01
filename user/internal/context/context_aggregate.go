package context

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
