package context

import (
	"path/filepath"
	"strings"
	"time"
)

const (
	// Keep only a bounded slice of recent history so per-session memory stays predictable.
	defaultRecentEventLimit = 64
	maxPerProcessArtifacts  = 16
	deepChainThreshold      = 4
	burstConnectThreshold   = 3
	burstExecThreshold      = 3
)

var burstWindow = 10 * time.Second

var suspiciousPathPatterns = []string{
	"/tmp/",
	"/var/tmp/",
	"/dev/shm/",
	"/run/user/",
	"/proc/self/fd/",
}

var sensitivePathPrefixes = []string{
	"/etc/",
	"/root/",
	"/home/",
	"/proc/",
	"/sys/",
	"/var/run/secrets/",
	"/run/secrets/",
	"/var/lib/kubelet/",
	"/var/lib/docker/",
	"/var/lib/containerd/",
}

var sensitivePathPatterns = []string{
	"/.ssh/",
	"/.gnupg/",
	"/.aws/",
	"/.azure/",
	"/.gcloud/",
	"/.kube/",
	"/.docker/",
	"/.config/",
	"/.npmrc",
	"/.pypirc",
	"/.netrc",
	"/id_rsa",
	"/id_ed25519",
	"/authorized_keys",
	"/known_hosts",
	"/credentials",
	"/credentials.json",
	"/token",
	"/secret",
	"/passwd",
	"/shadow",
	".env",
}

var shellNames = map[string]struct{}{
	"sh":   {},
	"bash": {},
	"zsh":  {},
	"dash": {},
	"ksh":  {},
	"fish": {},
}

var networkToolNames = map[string]struct{}{
	"curl":    {},
	"wget":    {},
	"nc":      {},
	"netcat":  {},
	"ncat":    {},
	"socat":   {},
	"ssh":     {},
	"scp":     {},
	"rsync":   {},
}

var interpreterNames = map[string]struct{}{
	"python":  {},
	"python3": {},
	"perl":    {},
	"ruby":    {},
	"node":    {},
	"php":     {},
	"lua":     {},
	"bash":    {},
	"sh":      {},
	"dash":    {},
	"zsh":     {},
}

var containerRuntimeNames = map[string]struct{}{
	"docker":     {},
	"containerd": {},
	"ctr":        {},
	"runc":       {},
	"crun":       {},
	"podman":     {},
	"nerdctl":    {},
}

// isSuspiciousPath marks common execution locations used by fileless or short-lived payloads.
func isSuspiciousPath(path string) bool {
	lower := normalizePath(path)
	if lower == "" {
		return false
	}

	for _, pattern := range suspiciousPathPatterns {
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

	for _, prefix := range sensitivePathPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	for _, pattern := range sensitivePathPatterns {
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

// appendUniqueEndpoint keeps a bounded de-duplicated set of recent remote destinations per session.
func appendUniqueEndpoint(items []Endpoint, endpoint Endpoint) []Endpoint {
	for _, item := range items {
		if item == endpoint {
			return items
		}
	}

	items = append(items, endpoint)
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

func lineageHasCommand(lineage []LineageNode, names map[string]struct{}) bool {
	for _, node := range lineage {
		name := normalizePath(basenameFromPath(node.Comm))
		if _, ok := names[name]; ok {
			return true
		}
	}
	return false
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
