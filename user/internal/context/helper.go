package context

import (
	"path/filepath"
	"strings"
)

// isSuspiciousPath marks common execution locations used by fileless or short-lived payloads.
func isSuspiciousPath(path string) bool {
	lower := normalizePath(path)
	if lower == "" {
		return false
	}

	for _, pattern := range CurrentHeuristics().SuspiciousPathPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return strings.HasPrefix(lower, "memfd:") || strings.Contains(lower, " (deleted)")
}

// isSensitivePath marks paths that are usually interesting for credential or system data access.
func isSensitivePath(path string) bool {
	lower := normalizePath(path)
	if lower == "" {
		return false
	}

	for _, prefix := range CurrentHeuristics().SensitivePathPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	for _, pattern := range CurrentHeuristics().SensitivePathPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

func isMemfdOrDeletedPath(path string) bool {
	lower := normalizePath(path)
	if lower == "" {
		return false
	}

	return strings.HasPrefix(lower, "memfd:") || strings.Contains(lower, " (deleted)")
}

func isDeletedPath(path string) bool {
	return strings.Contains(normalizePath(path), " (deleted)")
}

// trimOpenEvents keeps only the latest open artifacts for pattern matching.
func trimOpenEvents(items []ObservedOpen) []ObservedOpen {
	limit := CurrentHeuristics().MaxPerProcessArtifacts
	if len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}

// trimConnectEvents keeps only the latest connect artifacts for pattern matching.
func trimConnectEvents(items []ObservedConnect) []ObservedConnect {
	limit := CurrentHeuristics().MaxPerProcessArtifacts
	if len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}

// appendUniqueEndpoint keeps a bounded de-duplicated set of recent remote destinations per session.
func appendUniqueEndpoint(items []Endpoint, endpoint Endpoint) []Endpoint {
	for _, item := range items {
		if item == endpoint {
			return items
		}
	}

	items = append(items, endpoint)
	limit := CurrentHeuristics().MaxPerProcessArtifacts
	if len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}

// trimRecentEvents bounds session-level history used for historical context generation.
func trimRecentEvents(items []ObservedEvent, limit int) []ObservedEvent {
	if len(items) <= limit {
		return items
	}
	return items[len(items)-limit:]
}

func lineageHasCommand(lineage []LineageNode, names map[string]struct{}) bool {
	for _, node := range lineage {
		name := normalizePath(basenameFromPath(node.Comm))
		if _, ok := names[name]; ok {
			return true
		}
	}
	return false
}

func nameSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[normalizePath(item)] = struct{}{}
	}
	return out
}

func openHasWriteIntent(flags uint32) bool {
	const (
		oWRONLY = 1
		oRDWR   = 2
		oCREAT  = 0x40
		oTRUNC  = 0x200
		oAPPEND = 0x400
	)

	accessMode := flags & 0x3
	return accessMode == oWRONLY ||
		accessMode == oRDWR ||
		flags&oCREAT != 0 ||
		flags&oTRUNC != 0 ||
		flags&oAPPEND != 0
}

func basenameFromPath(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}

func normalizePath(path string) string {
	return strings.ToLower(strings.TrimSpace(path))
}
