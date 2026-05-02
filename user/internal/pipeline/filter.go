package pipeline

import (
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/cclts/casa/user/internal/event"
)

func ShouldIngestIntoContext(e event.Event) bool {
	return !isMissingStructuredFields(e) &&
		!isRuntimeLoaderNoise(e) &&
		!isRoutineSessionFileNoise(e) &&
		!isTransparentRoutineExec(e) &&
		!isIgnorableConnectNoise(e)
}

func isMissingStructuredFields(e event.Event) bool {
	switch e.Type {
	case event.EventOpenat:
		return strings.TrimSpace(e.Path) == ""
	case event.EventConnect:
		return strings.TrimSpace(e.Addr) == "" || e.Port == 0
	default:
		return false
	}
}

func isRuntimeLoaderNoise(e event.Event) bool {
	if e.Type != event.EventOpenat {
		return false
	}

	p := strings.ToLower(strings.TrimSpace(e.Path))
	if p == "" {
		return false
	}

	if p == "/etc/ld.so.cache" {
		return true
	}

	if strings.HasPrefix(p, "/lib/") ||
		strings.HasPrefix(p, "/usr/lib/") ||
		strings.HasPrefix(p, "/lib64/") {
		return strings.Contains(p, ".so")
	}

	if p == "/proc" || strings.HasPrefix(p, "/proc/") {
		return true
	}

	if strings.Contains(p, "/.nvm/") {
		return true
	}

	return false
}

func isTransparentRoutineExec(e event.Event) bool {
	if e.Type != event.EventExecve {
		return false
	}

	base := strings.ToLower(filepath.Base(strings.TrimSpace(e.Path)))
	switch base {
	case "uname":
		return matchesCommandArgs(e.Args, base, "-a")
	case "whoami", "pwd", "id":
		return matchesCommandArgs(e.Args, base)
	case "ip":
		return matchesCommandArgs(e.Args, base, "neigh", "show")
	default:
		return false
	}
}

func isRoutineSessionFileNoise(e event.Event) bool {
	if e.Type != event.EventOpenat {
		return false
	}

	p := strings.ToLower(strings.TrimSpace(e.Path))
	if p == "" {
		return false
	}

	if strings.Contains(p, "/.openclaw/") {
		return true
	}

	switch {
	case strings.HasSuffix(p, "/package.json"),
		strings.HasSuffix(p, "/package-lock.json"),
		strings.HasSuffix(p, "/etc/hosts"),
		strings.HasSuffix(p, "/.bashrc"),
		strings.HasSuffix(p, "/.profile"),
		strings.Contains(p, "/gconv/gconv-modules.cache"),
		strings.Contains(p, "/etc/bash.bashrc"):
		return true
	default:
		return false
	}
}

func isIgnorableConnectNoise(e event.Event) bool {
	if e.Type != event.EventConnect {
		return false
	}

	addr := strings.TrimSpace(e.Addr)
	if addr == "" || addr == "0.0.0.0" || e.Port == 0 {
		return true
	}

	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}

	if parsed.IsLoopback() {
		return true
	}

	return false
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

func matchesCommandArgs(args []string, command string, tail ...string) bool {
	if hasExactArgs(args, tail...) {
		return true
	}

	withProgram := append([]string{command}, tail...)
	return hasExactArgs(args, withProgram...)
}
