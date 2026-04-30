package context

// buildFileContext summarizes file-centric derived facts for the whole session.
func buildFileContext(state *SessionState) FileContext {
	return FileContext{
		WriteThenExecSamePath: detectWriteThenExecSamePath(state),
		OpenedDeletedPath:     detectOpenedDeletedPath(state),
	}
}

func detectWriteThenExecSamePath(state *SessionState) bool {
	if state == nil {
		return false
	}

	writtenPaths := make(map[string]struct{})
	execPaths := make(map[string]struct{})

	for _, procState := range state.Processes {
		if procState == nil {
			continue
		}

		for _, open := range procState.Opens {
			if openHasWriteIntent(open.Flags) {
				writtenPaths[normalizePath(open.Path)] = struct{}{}
			}
		}

		if procState.ExecPath != "" {
			execPaths[normalizePath(procState.ExecPath)] = struct{}{}
		}
	}

	for path := range execPaths {
		if _, ok := writtenPaths[path]; ok {
			return true
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
