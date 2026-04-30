package context

import "sort"

// BuildContext materializes a session-scoped context snapshot.
func BuildContext(state *SessionState, targetPID uint32) Context {
	ctx := Context{
		SessionID: state.ID,
		TargetPID: targetPID,
	}

	if state == nil {
		return ctx
	}

	ctx.ExecutionChains = buildExecutionChainContexts(state)
	ctx.Capabilities = buildCapabilityContexts(state)
	ctx.History = buildHistoricalContext(state)

	return ctx
}

func buildExecutionChainContexts(state *SessionState) []ExecutionChainContext {
	if state == nil {
		return nil
	}

	pids := sortedProcessIDs(state)
	out := make([]ExecutionChainContext, 0, len(pids))
	for _, pid := range pids {
		procState := state.Processes[pid]
		if procState == nil {
			continue
		}
		out = append(out, buildExecutionChainContext(state, procState))
	}

	return out
}

func buildCapabilityContexts(state *SessionState) []CapabilityContext {
	if state == nil {
		return nil
	}

	pids := sortedProcessIDs(state)
	out := make([]CapabilityContext, 0, len(pids))
	for _, pid := range pids {
		procState := state.Processes[pid]
		if procState == nil {
			continue
		}
		out = append(out, buildCapabilityContext(procState))
	}

	return out
}

func sortedProcessIDs(state *SessionState) []uint32 {
	pids := make([]uint32, 0, len(state.Processes))
	for _, procState := range state.Processes {
		if procState == nil {
			continue
		}
		pids = append(pids, procState.PID)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}
