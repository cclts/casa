package context

import (
	"github.com/cclts/casa/user/internal/event"
)

// buildHistoricalContext summarizes the recent syscall history observed for the process.
func buildHistoricalContext(state *SessionState, targetPID uint32) HistoricalContext {
	procState := state.Processes[targetPID]
	if procState == nil {
		return HistoricalContext{}
	}

	recent := make([]string, 0, len(state.RecentEvents))
	var firstEventUnix int64
	var lastEventUnix int64

	for _, evt := range state.RecentEvents {
		if evt.PID != targetPID {
			continue
		}

		recent = append(recent, evt.Type.String())

		unix := evt.Time.Unix()
		if firstEventUnix == 0 || unix < firstEventUnix {
			firstEventUnix = unix
		}
		if unix > lastEventUnix {
			lastEventUnix = unix
		}
	}

	return HistoricalContext{
		RecentSyscalls:       recent,
		ExecCount:            procState.ExecCount,
		OpenCount:            procState.OpenCount,
		ConnectCount:         procState.ConnectCount,
		TimeWindowSeconds:    lastEventUnix - firstEventUnix,
		ConnectThenExec:      detectConnectThenExec(state.RecentEvents, targetPID),
		SensitiveThenNetwork: detectSensitiveThenNetwork(procState),
		SensitiveThenExecve:  detectSensitiveThenExecve(state.RecentEvents, procState, targetPID),
		BurstConnect:         detectBurstEvent(state.RecentEvents, targetPID, event.EventConnect, CurrentHeuristics().BurstConnectThreshold),
		BurstExec:            detectBurstEvent(state.RecentEvents, targetPID, event.EventExecve, CurrentHeuristics().BurstExecThreshold),
		UniqueOpenPathCount:  uniqueOpenPathCount(procState.Opens),
	}
}

func detectConnectThenExec(events []ObservedEvent, targetPID uint32) bool {
	var seenConnect bool
	for _, evt := range events {
		if evt.PID != targetPID {
			continue
		}
		if evt.Type == event.EventConnect {
			seenConnect = true
			continue
		}
		if seenConnect && evt.Type == event.EventExecve {
			return true
		}
	}
	return false
}

func detectSensitiveThenNetwork(procState *ProcessState) bool {
	window := CurrentHeuristics().SensitiveHistoryWindow
	for _, open := range procState.Opens {
		if !isSensitivePath(open.Path) {
			continue
		}
		for _, conn := range procState.Connects {
			if conn.Time.Before(open.Time) {
				continue
			}
			if window <= 0 || conn.Time.Sub(open.Time) <= window {
				return true
			}
		}
	}
	return false
}

func detectSensitiveThenExecve(events []ObservedEvent, procState *ProcessState, targetPID uint32) bool {
	if procState.ExecCount == 0 {
		return false
	}

	var seenSensitive bool
	var sensitiveAtUnix int64
	windowSeconds := int64(CurrentHeuristics().SensitiveHistoryWindow.Seconds())
	for _, evt := range events {
		if evt.PID != targetPID {
			continue
		}
		if evt.Type == event.EventOpenat && isSensitivePath(evt.Path) {
			seenSensitive = true
			sensitiveAtUnix = evt.Time.Unix()
			continue
		}
		if seenSensitive && evt.Type == event.EventExecve {
			if windowSeconds > 0 && evt.Time.Unix()-sensitiveAtUnix > windowSeconds {
				seenSensitive = false
				continue
			}
			return true
		}
	}

	return false
}

func detectBurstEvent(events []ObservedEvent, targetPID uint32, eventType event.EventType, threshold int) bool {
	if threshold <= 1 {
		return true
	}

	window := make([]ObservedEvent, 0, threshold)
	for _, evt := range events {
		if evt.PID != targetPID || evt.Type != eventType {
			continue
		}

		window = append(window, evt)
		if len(window) < threshold {
			continue
		}

		first := window[len(window)-threshold]
		if evt.Time.Sub(first.Time) <= CurrentHeuristics().BurstWindow {
			return true
		}
	}

	return false
}

func uniqueOpenPathCount(items []ObservedOpen) int {
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		if item.Path == "" {
			continue
		}
		seen[item.Path] = struct{}{}
	}
	return len(seen)
}
