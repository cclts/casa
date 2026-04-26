package context

// buildFileContext summarizes file-centric derived facts for the target process.
func buildFileContext(procState *ProcessState) FileContext {
	return FileContext{
		WriteThenExecSamePath: detectWriteThenExecSamePath(procState),
		OpenedDeletedPath:     detectOpenedDeletedPath(procState),
	}
}

func detectWriteThenExecSamePath(procState *ProcessState) bool {
	if procState.ExecPath == "" {
		return false
	}

	for _, open := range procState.Opens {
		if open.Path == procState.ExecPath && openHasWriteIntent(open.Flags) {
			return true
		}
	}

	return false
}

func detectOpenedDeletedPath(procState *ProcessState) bool {
	for _, open := range procState.Opens {
		if isDeletedPath(open.Path) {
			return true
		}
	}
	return false
}
