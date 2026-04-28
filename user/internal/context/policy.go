package context

import (
	"sync"
	"time"
)

// Heuristics centralizes all non-rule context derivation knobs.
type Heuristics struct {
	RecentEventLimit       int
	MaxPerProcessArtifacts int
	DeepChainThreshold     int
	BurstConnectThreshold  int
	BurstExecThreshold     int
	BurstWindow            time.Duration
	SensitiveHistoryWindow time.Duration

	SuspiciousPathPatterns []string
	SensitivePathPrefixes  []string
	SensitivePathPatterns  []string

	ShellNames            []string
	NetworkToolNames      []string
	InterpreterNames      []string
	ContainerRuntimeNames []string
}

var defaultHeuristics = Heuristics{
	RecentEventLimit:       64,
	MaxPerProcessArtifacts: 16,
	DeepChainThreshold:     5,
	BurstConnectThreshold:  3,
	BurstExecThreshold:     3,
	BurstWindow:            10 * time.Second,
	SensitiveHistoryWindow: 30 * time.Second,
	SuspiciousPathPatterns: []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/proc/self/fd/"},
	SensitivePathPrefixes:  []string{"/etc/", "/root/", "/home/", "/proc/", "/sys/", "/var/run/secrets/", "/run/secrets/", "/var/lib/kubelet/", "/var/lib/docker/", "/var/lib/containerd/"},
	SensitivePathPatterns:  []string{"/.ssh/", "/.gnupg/", "/.aws/", "/.azure/", "/.gcloud/", "/.kube/", "/.docker/", "/.config/", "/.npmrc", "/.pypirc", "/.netrc", "/id_rsa", "/id_ed25519", "/authorized_keys", "/known_hosts", "/credentials", "/credentials.json", "/token", "/secret", "/passwd", "/shadow", ".env"},
	ShellNames:             []string{"sh", "bash", "zsh", "dash", "ksh", "fish"},
	NetworkToolNames:       []string{"curl", "wget", "nc", "netcat", "ncat", "socat", "ssh", "scp", "rsync"},
	InterpreterNames:       []string{"python", "python3", "perl", "ruby", "node", "php", "lua", "bash", "sh", "dash", "zsh"},
	ContainerRuntimeNames:  []string{"docker", "containerd", "ctr", "runc", "crun", "podman", "nerdctl"},
}

var (
	heuristicsMu     sync.RWMutex
	activeHeuristics = cloneHeuristics(defaultHeuristics)
)

// ConfigureHeuristics replaces the active context heuristic set.
func ConfigureHeuristics(h Heuristics) {
	heuristicsMu.Lock()
	defer heuristicsMu.Unlock()
	activeHeuristics = normalizeHeuristics(h)
}

// CurrentHeuristics returns a copy of the active context heuristic set.
func CurrentHeuristics() Heuristics {
	heuristicsMu.RLock()
	defer heuristicsMu.RUnlock()
	return cloneHeuristics(activeHeuristics)
}

func normalizeHeuristics(h Heuristics) Heuristics {
	out := cloneHeuristics(defaultHeuristics)

	if h.RecentEventLimit > 0 {
		out.RecentEventLimit = h.RecentEventLimit
	}
	if h.MaxPerProcessArtifacts > 0 {
		out.MaxPerProcessArtifacts = h.MaxPerProcessArtifacts
	}
	if h.DeepChainThreshold > 0 {
		out.DeepChainThreshold = h.DeepChainThreshold
	}
	if h.BurstConnectThreshold > 0 {
		out.BurstConnectThreshold = h.BurstConnectThreshold
	}
	if h.BurstExecThreshold > 0 {
		out.BurstExecThreshold = h.BurstExecThreshold
	}
	if h.BurstWindow > 0 {
		out.BurstWindow = h.BurstWindow
	}
	if h.SensitiveHistoryWindow > 0 {
		out.SensitiveHistoryWindow = h.SensitiveHistoryWindow
	}

	if len(h.SuspiciousPathPatterns) > 0 {
		out.SuspiciousPathPatterns = append([]string(nil), h.SuspiciousPathPatterns...)
	}
	if len(h.SensitivePathPrefixes) > 0 {
		out.SensitivePathPrefixes = append([]string(nil), h.SensitivePathPrefixes...)
	}
	if len(h.SensitivePathPatterns) > 0 {
		out.SensitivePathPatterns = append([]string(nil), h.SensitivePathPatterns...)
	}
	if len(h.ShellNames) > 0 {
		out.ShellNames = append([]string(nil), h.ShellNames...)
	}
	if len(h.NetworkToolNames) > 0 {
		out.NetworkToolNames = append([]string(nil), h.NetworkToolNames...)
	}
	if len(h.InterpreterNames) > 0 {
		out.InterpreterNames = append([]string(nil), h.InterpreterNames...)
	}
	if len(h.ContainerRuntimeNames) > 0 {
		out.ContainerRuntimeNames = append([]string(nil), h.ContainerRuntimeNames...)
	}

	return out
}

func cloneHeuristics(h Heuristics) Heuristics {
	h.SuspiciousPathPatterns = append([]string(nil), h.SuspiciousPathPatterns...)
	h.SensitivePathPrefixes = append([]string(nil), h.SensitivePathPrefixes...)
	h.SensitivePathPatterns = append([]string(nil), h.SensitivePathPatterns...)
	h.ShellNames = append([]string(nil), h.ShellNames...)
	h.NetworkToolNames = append([]string(nil), h.NetworkToolNames...)
	h.InterpreterNames = append([]string(nil), h.InterpreterNames...)
	h.ContainerRuntimeNames = append([]string(nil), h.ContainerRuntimeNames...)
	return h
}
