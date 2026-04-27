package pipeline

import (
	"strings"

	"github.com/cclts/casa/user/internal/event"
)

func ShouldDropEvent(e event.Event) bool {
	return isRuntimeLoaderNoise(e)
}

func isRuntimeLoaderNoise(e event.Event) bool {
	if e.Type != event.OPENAT {
		return false
	}

	p := e.Path

	if p == "/etc/ld.so.cache" {
		return true
	}

	if strings.HasPrefix(p, "/lib/") ||
		strings.HasPrefix(p, "/usr/lib/") ||
		strings.HasPrefix(p, "/lib64/") {
		return strings.Contains(p, ".so")
	}

	return false
}

func IsRoutineDiscoveryCommand(e event.Event) bool {
	if e.Type != event.EXECVE {
		return false
	}

	return e.Path == "/usr/bin/ip" &&
		len(e.Args) >= 3 &&
		e.Args[1] == "neigh" &&
		e.Args[2] == "show"
}