package context

// buildFileContext summarizes file-centric derived facts for the whole session.
func buildFileContext(state *SessionState) FileContext {
	return FileContext{
		WriteThenExecSamePath: detectWriteThenExecSamePath(state),
		OpenedDeletedPath:     detectOpenedDeletedPath(state),
	}
}

func detectWriteThenExecSamePath(state *SessionState) bool {
	for _, procState := range state.Processes {
		if procState.ExecPath == "" {
			continue
		}
		for _, open := range procState.Opens {
			if open.Path == procState.ExecPath && openHasWriteIntent(open.Flags) {
				return true
			}
		}
	}
	return false
}

func detectOpenedDeletedPath(state *SessionState) bool {
	for _, procState := range state.Processes {
		for _, open := range procState.Opens {
			if isDeletedPath(open.Path) {
				return true
			}
		}
	}
	return false
}
