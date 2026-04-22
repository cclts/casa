package context

import "strings"

const (
	// Keep only a bounded slice of recent history so per-session memory stays predictable.
	defaultRecentEventLimit = 64
	maxPerProcessArtifacts  = 16
)

// isSuspiciousPath marks common execution locations used by fileless or short-lived payloads.
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

// isSensitivePath marks paths that are usually interesting for credential or system data access.
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

// trimOpenEvents keeps only the latest open artifacts for pattern matching.
func trimOpenEvents(items []ObservedOpen) []ObservedOpen {
	if len(items) <= maxPerProcessArtifacts {
		return items
	}
	return items[len(items)-maxPerProcessArtifacts:]
}

// trimConnectEvents keeps only the latest connect artifacts for pattern matching.
func trimConnectEvents(items []ObservedConnect) []ObservedConnect {
	if len(items) <= maxPerProcessArtifacts {
		return items
	}
	return items[len(items)-maxPerProcessArtifacts:]
}

// trimRecentEvents bounds session-level history used for historical context generation.
func trimRecentEvents(items []ObservedEvent, limit int) []ObservedEvent {
	if len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}
