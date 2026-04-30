package context

import (
	"net/netip"

	"github.com/cclts/casa/user/internal/event"
)

// buildHistoricalContext summarizes the recent syscall history observed for the whole session.
func buildHistoricalContext(state *SessionState) HistoricalContext {
	recent := make([]string, 0, len(state.RecentEvents))
	var firstEventUnix int64
	var lastEventUnix int64
	var execCount, openCount, connectCount int

	for _, evt := range state.RecentEvents {
		recent = append(recent, evt.Type.String())

		unix := evt.Time.Unix()
		if firstEventUnix == 0 || unix < firstEventUnix {
			firstEventUnix = unix
		}
		if unix > lastEventUnix {
			lastEventUnix = unix
		}
	}
	for _, procState := range state.Processes {
		execCount += procState.ExecCount
		openCount += procState.OpenCount
		connectCount += procState.ConnectCount
	}

	return HistoricalContext{
		RecentSyscalls:        recent,
		ExecCount:             execCount,
		OpenCount:             openCount,
		ConnectCount:          connectCount,
		TimeWindowSeconds:     lastEventUnix - firstEventUnix,
		ConnectThenExec:       detectConnectThenExec(state.RecentEvents),
		SensitiveThenNetwork:  detectSensitiveThenNetwork(state),
		SensitiveThenExecve:   detectSensitiveThenExecve(state.RecentEvents),
		BurstConnect:          detectBurstEvent(state.RecentEvents, event.EventConnect, CurrentHeuristics().BurstConnectThreshold),
		BurstExec:             detectBurstEvent(state.RecentEvents, event.EventExecve, CurrentHeuristics().BurstExecThreshold),
		UniqueOpenPathCount:   uniqueSessionOpenPathCount(state),
		WriteThenExecSamePath: detectWriteThenExecSamePath(state),
		OpenedDeletedPath:     detectOpenedDeletedPath(state),
	}
}

func detectConnectThenExec(events []ObservedEvent) bool {
	var seenConnect bool
	for _, evt := range events {
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

func detectSensitiveThenNetwork(state *SessionState) bool {
	window := CurrentHeuristics().SensitiveHistoryWindow
	for _, procState := range state.Processes {
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
	}
	return false
}

func detectSensitiveThenExecve(events []ObservedEvent) bool {
	var seenSensitive bool
	var sensitiveAtUnix int64
	windowSeconds := int64(CurrentHeuristics().SensitiveHistoryWindow.Seconds())
	for _, evt := range events {
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

func detectBurstEvent(events []ObservedEvent, eventType event.EventType, threshold int) bool {
	if threshold <= 1 {
		return true
	}

	window := make([]ObservedEvent, 0, threshold)
	for _, evt := range events {
		if evt.Type != eventType {
			continue
		}
		if eventType == event.EventConnect && shouldIgnoreBurstConnect(evt) {
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

func uniqueSessionOpenPathCount(state *SessionState) int {
	seen := make(map[string]struct{})
	for _, procState := range state.Processes {
		for _, item := range procState.Opens {
			if item.Path == "" {
				continue
			}
			seen[item.Path] = struct{}{}
		}
	}
	return len(seen)
}

func shouldIgnoreBurstConnect(evt ObservedEvent) bool {
	if evt.Type != event.EventConnect {
		return false
	}

	addr, err := netip.ParseAddr(normalizePath(evt.Addr))
	if err != nil {
		return false
	}

	if addr.IsLoopback() {
		return true
	}

	if addr.Is4() {
		if inPrefix(addr, "169.254.0.0/16") ||
			inPrefix(addr, "10.0.0.0/8") ||
			inPrefix(addr, "172.16.0.0/12") ||
			inPrefix(addr, "192.168.0.0/16") {
			return true
		}
	}

	// Local stub resolvers commonly sit on loopback or private/link-local
	// addresses; they should not contribute to burst-connect detection.
	if evt.Port == 53 && (addr.IsLoopback() || isPrivateOrLinkLocal(addr)) {
		return true
	}

	return false
}

func isPrivateOrLinkLocal(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Is4() {
		return inPrefix(addr, "169.254.0.0/16") ||
			inPrefix(addr, "10.0.0.0/8") ||
			inPrefix(addr, "172.16.0.0/12") ||
			inPrefix(addr, "192.168.0.0/16")
	}
	return addr == netip.MustParseAddr("::1")
}

func inPrefix(addr netip.Addr, cidr string) bool {
	prefix := netip.MustParsePrefix(cidr)
	return prefix.Contains(addr)
}
