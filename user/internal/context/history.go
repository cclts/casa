package context

import (
	"net/netip"
	"strings"
	"time"

	"github.com/cclts/casa/user/internal/diag"
	"github.com/cclts/casa/user/internal/event"
)

// BuildHistoricalContext summarizes the recent syscall history observed for the whole session.
func BuildHistoricalContext(snapshot SessionSnapshot) HistoricalContext {
	history := HistoricalContext{
		ConnectThenExec:       detectConnectThenExec(snapshot),
		SensitiveThenNetwork:  detectSensitiveThenNetwork(snapshot),
		SensitiveThenExecve:   detectSensitiveThenExecve(snapshot),
		BurstOpen:             detectBurstEvent(snapshot, event.EventOpenat, CurrentHeuristics().BurstOpenThreshold),
		BurstConnect:          detectBurstEvent(snapshot, event.EventConnect, CurrentHeuristics().BurstConnectThreshold),
		BurstExec:             detectBurstEvent(snapshot, event.EventExecve, CurrentHeuristics().BurstExecThreshold),
		WriteThenExecSamePath: detectWriteThenExecSamePath(snapshot),
		OpenedDeletedPath:     detectOpenedDeletedPath(snapshot),
	}
	if diag.Enabled() {
		diag.Logf("[HISTORY DEBUG] session=%d events=%d connect_then_exec=%t sensitive_then_network=%t sensitive_then_execve=%t burst_open=%t burst_connect=%t burst_exec=%t write_then_exec_same_path=%t opened_deleted_path=%t",
			snapshot.ID,
			len(snapshot.RecentEvents),
			history.ConnectThenExec,
			history.SensitiveThenNetwork,
			history.SensitiveThenExecve,
			history.BurstOpen,
			history.BurstConnect,
			history.BurstExec,
			history.WriteThenExecSamePath,
			history.OpenedDeletedPath,
		)
	}
	return history
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
	window := CurrentHeuristics().SensitiveHistoryWindow
	var lastSensitiveAt time.Time
	var lastConnectAt time.Time

	for _, evt := range snapshot.RecentEvents {
		switch evt.Type {
		case event.EventOpenat:
			if !isSensitivePath(evt.Path) {
				continue
			}
			lastSensitiveAt = evt.Time
			diag.Logf("[HISTORY DEBUG] session=%d sensitive_open path=%s ts=%s", snapshot.ID, evt.Path, evt.Time.Format(time.RFC3339Nano))
			if withinHistoryWindow(lastConnectAt, lastSensitiveAt, window) {
				diag.Logf("[HISTORY DEBUG] session=%d sensitive_then_network matched direction=connect_before_open connect_ts=%s open_ts=%s window=%s",
					snapshot.ID,
					lastConnectAt.Format(time.RFC3339Nano),
					lastSensitiveAt.Format(time.RFC3339Nano),
					window,
				)
				return true
			}
		case event.EventConnect:
			lastConnectAt = evt.Time
			diag.Logf("[HISTORY DEBUG] session=%d connect addr=%s port=%d ts=%s", snapshot.ID, evt.Addr, evt.Port, evt.Time.Format(time.RFC3339Nano))
			if withinHistoryWindow(lastSensitiveAt, lastConnectAt, window) {
				diag.Logf("[HISTORY DEBUG] session=%d sensitive_then_network matched direction=open_before_connect open_ts=%s connect_ts=%s window=%s",
					snapshot.ID,
					lastSensitiveAt.Format(time.RFC3339Nano),
					lastConnectAt.Format(time.RFC3339Nano),
					window,
				)
				return true
			}
		}
	}
	return false
}

func detectSensitiveThenExecve(snapshot SessionSnapshot) bool {
	window := CurrentHeuristics().SensitiveHistoryWindow
	var lastSensitiveAt time.Time
	var lastExecAt time.Time

	for _, evt := range snapshot.RecentEvents {
		switch evt.Type {
		case event.EventOpenat:
			if !isSensitivePath(evt.Path) {
				continue
			}
			lastSensitiveAt = evt.Time
			diag.Logf("[HISTORY DEBUG] session=%d sensitive_open path=%s ts=%s", snapshot.ID, evt.Path, evt.Time.Format(time.RFC3339Nano))
			if withinHistoryWindow(lastExecAt, lastSensitiveAt, window) {
				diag.Logf("[HISTORY DEBUG] session=%d sensitive_then_execve matched direction=exec_before_open exec_ts=%s open_ts=%s window=%s",
					snapshot.ID,
					lastExecAt.Format(time.RFC3339Nano),
					lastSensitiveAt.Format(time.RFC3339Nano),
					window,
				)
				return true
			}
		case event.EventExecve:
			lastExecAt = evt.Time
			diag.Logf("[HISTORY DEBUG] session=%d exec path=%s ts=%s", snapshot.ID, evt.Path, evt.Time.Format(time.RFC3339Nano))
			if withinHistoryWindow(lastSensitiveAt, lastExecAt, window) {
				diag.Logf("[HISTORY DEBUG] session=%d sensitive_then_execve matched direction=open_before_exec open_ts=%s exec_ts=%s window=%s",
					snapshot.ID,
					lastSensitiveAt.Format(time.RFC3339Nano),
					lastExecAt.Format(time.RFC3339Nano),
					window,
				)
				return true
			}
		}
	}

	return false
}

func withinHistoryWindow(a, b time.Time, window time.Duration) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	diff := a.Sub(b)
	if diff < 0 {
		diff = -diff
	}
	if window <= 0 {
		return true
	}
	return diff <= window
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
