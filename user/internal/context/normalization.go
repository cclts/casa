package context

import (
	"path/filepath"
	"strings"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

func normalizeIgnoredEvent(suppressed map[process.SessionID]map[uint32]struct{}, sessionID process.SessionID, session *SessionState, e event.Event) bool {
	if session == nil {
		return false
	}

	switch e.Type {
	case event.EventExecve:
		if !isTransparentRoutineExecEvent(e) {
			return false
		}
		return pruneTransparentRoutineShell(suppressed, sessionID, session, e.PPID)
	case event.EventExit:
		shells := suppressed[sessionID]
		if shells == nil {
			return false
		}
		if _, ok := shells[e.PID]; !ok {
			return false
		}
		delete(shells, e.PID)
		if len(shells) == 0 {
			delete(suppressed, sessionID)
		}
		return true
	default:
		return false
	}
}

func pruneTransparentRoutineShell(suppressed map[process.SessionID]map[uint32]struct{}, sessionID process.SessionID, session *SessionState, shellPID uint32) bool {
	if session == nil {
		return false
	}

	procState := session.Processes[shellPID]
	if procState == nil || !isRoutineShellProcess(procState) {
		return false
	}

	delete(session.Processes, shellPID)

	filtered := session.RecentEvents[:0]
	for _, evt := range session.RecentEvents {
		if evt.PID == shellPID {
			continue
		}
		filtered = append(filtered, evt)
	}
	session.RecentEvents = filtered

	if _, ok := suppressed[sessionID]; !ok {
		suppressed[sessionID] = make(map[uint32]struct{})
	}
	suppressed[sessionID][shellPID] = struct{}{}
	return true
}

func isRoutineShellProcess(procState *ProcessState) bool {
	if procState == nil {
		return false
	}
	if len(procState.Opens) != 0 || len(procState.Connects) != 0 {
		return false
	}

	name := strings.ToLower(strings.TrimSpace(procState.Comm))
	if name == "" && procState.ExecPath != "" {
		name = strings.ToLower(filepath.Base(strings.TrimSpace(procState.ExecPath)))
	}
	switch name {
	case "sh", "bash", "dash", "zsh":
		return true
	default:
		return false
	}
}

func isTransparentRoutineExecEvent(e event.Event) bool {
	if e.Type != event.EventExecve {
		return false
	}
	base := strings.ToLower(filepath.Base(strings.TrimSpace(e.Path)))
	switch base {
	case "uname":
		return hasExactArgs(argsWithoutProgram(e.Args), "-a")
	case "whoami", "pwd", "id":
		return len(argsWithoutProgram(e.Args)) == 0
	case "ip":
		return hasExactArgs(argsWithoutProgram(e.Args), "neigh", "show")
	default:
		return false
	}
}

func argsWithoutProgram(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

func hasExactArgs(args []string, expected ...string) bool {
	if len(args) != len(expected) {
		return false
	}
	for i := range expected {
		if args[i] != expected[i] {
			return false
		}
	}
	return true
}
