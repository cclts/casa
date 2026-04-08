package context

import (
	"strings"
)

func collectNodes(root *ProcNode) []*ProcNode {
	var result []*ProcNode

	var dfs func(n *ProcNode)
	dfs = func(n *ProcNode) {
		if n == nil {
			return
		}
		result = append(result, n)
		for _, c := range n.Children {
			dfs(c)
		}
	}

	dfs(root)
	return result
}

func computeDepth(root *ProcNode) int {
	if root == nil {
		return 0
	}

	maxDepth := 0

	var dfs func(n *ProcNode, depth int)
	dfs = func(n *ProcNode, depth int) {
		if depth > maxDepth {
			maxDepth = depth
		}
		for _, c := range n.Children {
			dfs(c, depth+1)
		}
	}

	dfs(root, 1)
	return maxDepth
}

func isSuspiciousPath(p string) bool {
	return strings.Contains(p, "/tmp") ||
		strings.Contains(p, "/dev/shm") ||
		strings.Contains(p, "(deleted)") ||
		strings.Contains(p, "memfd")
}

func hasSensitiveFile(opens []string) bool {
	for _, p := range opens {
		if strings.Contains(p, "/etc/passwd") ||
			strings.Contains(p, "/etc/shadow") {
			return true
		}
	}
	return false
}

func matchSuspiciousChain(root *ProcNode) bool {

	var dfs func(n *ProcNode) bool

	dfs = func(n *ProcNode) bool {
		if n == nil {
			return false
		}

		if strings.Contains(n.ExecPath, "bash") {
			for _, c1 := range n.Children {
				if strings.Contains(c1.ExecPath, "curl") || strings.Contains(c1.ExecPath, "wget") {
					for _, c2 := range c1.Children {
						if strings.Contains(c2.ExecPath, "sh") {
							return true
						}
					}
				}
			}
		}

		for _, c := range n.Children {
			if dfs(c) {
				return true
			}
		}

		return false
	}

	return dfs(root)
}

func copyMap(m map[string]bool) map[string]bool {
	n := make(map[string]bool)
	for k, v := range m {
		n[k] = v
	}
	return n
}

func detectConnectThenExec(nodes []*ProcNode) bool {

	for _, n := range nodes {

		if len(n.Connects) > 0 && n.HasExec {
			return true
		}
	}

	return false
}

func detectSensitiveThenConnect(nodes []*ProcNode) bool {

	for _, n := range nodes {

		hasSensitive := false

		for _, f := range n.Opens {
			if strings.Contains(f, "/etc/passwd") ||
				strings.Contains(f, "/etc/shadow") {
				hasSensitive = true
				break
			}
		}

		if hasSensitive && len(n.Connects) > 0 {
			return true
		}
	}

	return false
}
