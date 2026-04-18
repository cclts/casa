package context

import "strings"

const (
	defaultRecentEventLimit = 64
	maxPerProcessArtifacts  = 16
	deepChainThreshold      = 4
)

func isSuspiciousPath(path string) bool {
	if path == "" {
		return false
	}

	lower := strings.ToLower(path)
	return strings.Contains(lower, "/tmp/") ||
		strings.HasPrefix(lower, "memfd:") ||
		strings.Contains(lower, " (deleted)") ||
		strings.Contains(lower, "/dev/shm/")
}

func isSensitivePath(path string) bool {
	if path == "" {
		return false
	}

	lower := strings.ToLower(path)
	sensitivePrefixes := []string{
		"/etc/",
		"/root/",
		"/home/",
		"/var/run/secrets/",
		"/run/secrets/",
		"/proc/",
	}

	for _, prefix := range sensitivePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	return false
}

func trimOpenEvents(items []ObservedOpen) []ObservedOpen {
	if len(items) <= maxPerProcessArtifacts {
		return items
	}
	return items[len(items)-maxPerProcessArtifacts:]
}

func trimConnectEvents(items []ObservedConnect) []ObservedConnect {
	if len(items) <= maxPerProcessArtifacts {
		return items
	}
	return items[len(items)-maxPerProcessArtifacts:]
}

func trimRecentEvents(items []ObservedEvent, limit int) []ObservedEvent {
	if len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}
