package pipeline

import (
	"path/filepath"
	"strings"

	"github.com/cclts/casa/user/internal/event"
)

func ShouldIngestIntoContext(e event.Event) bool {
	return !isRuntimeLoaderNoise(e) && !isTransparentRoutineExec(e)
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
		return hasExactArgs(e.Args, "-a")
	case "whoami", "pwd", "id":
		return len(e.Args) == 0
	case "ip":
		return hasExactArgs(e.Args, "neigh", "show")
	default:
		return false
	}
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
