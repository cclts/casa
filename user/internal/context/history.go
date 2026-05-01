package context

import (
	"net/netip"
	"strings"
	"time"

	"github.com/cclts/casa/user/internal/event"
)

// BuildHistoricalContext summarizes the recent syscall history observed for the whole session.
func BuildHistoricalContext(snapshot SessionSnapshot) HistoricalContext {
	return HistoricalContext{
		ConnectThenExec:       detectConnectThenExec(snapshot),
		SensitiveThenNetwork:  detectSensitiveThenNetwork(snapshot),
		SensitiveThenExecve:   detectSensitiveThenExecve(snapshot),
		BurstOpen:             detectBurstEvent(snapshot, event.EventOpenat, CurrentHeuristics().BurstOpenThreshold),
		BurstConnect:          detectBurstEvent(snapshot, event.EventConnect, CurrentHeuristics().BurstConnectThreshold),
		BurstExec:             detectBurstEvent(snapshot, event.EventExecve, CurrentHeuristics().BurstExecThreshold),
		WriteThenExecSamePath: detectWriteThenExecSamePath(snapshot),
		OpenedDeletedPath:     detectOpenedDeletedPath(snapshot),
	}
}

func detectWriteThenExecSamePath(snapshot SessionSnapshot) bool {
	if snapshot.RecentEvents == nil {
		return false
	}

	writtenPaths := make(map[string]struct{}, len(snapshot.RecentEvents))
	for _, evt := range snapshot.RecentEvents {
		switch evt.Type {
		case event.EventOpenat:
			if openHasWriteIntent(evt.Flags) {
				writtenPaths[normalizePath(evt.Path)] = struct{}{}
			}
		case event.EventExecve:
			if _, ok := writtenPaths[normalizePath(evt.Path)]; ok {
				return true
			}
		}
	}
	return false
}

func detectConnectThenExec(snapshot SessionSnapshot) bool {
	var seenConnect bool
	for _, evt := range snapshot.RecentEvents {
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

func detectSensitiveThenNetwork(snapshot SessionSnapshot) bool {
	var seenSensitive bool
	var sensitiveAt time.Time
	window := CurrentHeuristics().SensitiveHistoryWindow

	for _, evt := range snapshot.RecentEvents {
		switch evt.Type {
		case event.EventOpenat:
			if isSensitivePath(evt.Path) {
				seenSensitive = true
				sensitiveAt = evt.Time
			}
		case event.EventConnect:
			if !seenSensitive {
				continue
			}
			if window <= 0 || !evt.Time.Before(sensitiveAt) && evt.Time.Sub(sensitiveAt) <= window {
				return true
			}
			if window > 0 && evt.Time.Sub(sensitiveAt) > window {
				seenSensitive = false
			}
		}
	}
	return false
}

func detectSensitiveThenExecve(snapshot SessionSnapshot) bool {
	var seenSensitive bool
	var sensitiveAtUnix int64
	windowSeconds := int64(CurrentHeuristics().SensitiveHistoryWindow.Seconds())
	for _, evt := range snapshot.RecentEvents {
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

func detectBurstEvent(snapshot SessionSnapshot, eventType event.EventType, threshold int) bool {
	if threshold <= 1 {
		return true
	}

	window := make([]ObservedEvent, 0, threshold)
	for _, evt := range snapshot.RecentEvents {
		if evt.Type != eventType {
			continue
		}
		if eventType == event.EventOpenat && shouldIgnoreBurstOpen(evt) {
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

func shouldIgnoreBurstOpen(evt ObservedEvent) bool {
	if evt.Type != event.EventOpenat {
		return false
	}

	p := normalizePath(evt.Path)
	if p == "" {
		return true
	}

	if p == "/etc/ld.so.cache" {
		return true
	}

	if strings.HasPrefix(p, "/lib/") ||
		strings.HasPrefix(p, "/usr/lib/") ||
		strings.HasPrefix(p, "/lib64/") {
		return strings.Contains(p, ".so")
	}

	if p == "/proc" || strings.HasPrefix(p, "/proc/") || p == "/sys" || strings.HasPrefix(p, "/sys/") {
		return true
	}

	if strings.Contains(p, "/.nvm/") {
		return true
	}

	if strings.HasSuffix(p, "/package.json") || strings.HasSuffix(p, "/package-lock.json") {
		return true
	}

	if strings.Contains(p, "/.openclaw/") {
		return true
	}

	switch p {
	case "/dev/null", "/dev/tty", "/dev/urandom", "/etc/localtime", "/usr/lib/locale/locale-archive":
		return true
	case "/home/ubuntu/.profile", "/home/ubuntu/.bashrc", "package.json", "package-lock.json":
		return true
	}

	return false
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
