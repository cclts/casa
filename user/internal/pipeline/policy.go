package pipeline

import (
	"net/netip"
	"strings"
	"sync"

	"github.com/cclts/casa/user/internal/rules"
)

type FilterPolicy struct {
	AllowedLoopbackPorts map[uint16]struct{}
	IgnoredConnectIPs    map[netip.Addr]struct{}
}

var (
	filterPolicyMu sync.RWMutex
	filterPolicy   = FilterPolicy{
		AllowedLoopbackPorts: make(map[uint16]struct{}),
		IgnoredConnectIPs:    make(map[netip.Addr]struct{}),
	}
)

func ConfigureFilters(analysis rules.AnalysisConfig) {
	policy := FilterPolicy{
		AllowedLoopbackPorts: make(map[uint16]struct{}, len(analysis.AllowedLoopbackPorts)),
		IgnoredConnectIPs:    make(map[netip.Addr]struct{}, len(analysis.IgnoredConnectIPs)),
	}

	for _, port := range analysis.AllowedLoopbackPorts {
		policy.AllowedLoopbackPorts[port] = struct{}{}
	}

	for _, raw := range analysis.IgnoredConnectIPs {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		policy.IgnoredConnectIPs[addr.Unmap()] = struct{}{}
	}

	filterPolicyMu.Lock()
	filterPolicy = policy
	filterPolicyMu.Unlock()
}

func currentFilterPolicy() FilterPolicy {
	filterPolicyMu.RLock()
	defer filterPolicyMu.RUnlock()

	out := FilterPolicy{
		AllowedLoopbackPorts: make(map[uint16]struct{}, len(filterPolicy.AllowedLoopbackPorts)),
		IgnoredConnectIPs:    make(map[netip.Addr]struct{}, len(filterPolicy.IgnoredConnectIPs)),
	}
	for port := range filterPolicy.AllowedLoopbackPorts {
		out.AllowedLoopbackPorts[port] = struct{}{}
	}
	for addr := range filterPolicy.IgnoredConnectIPs {
		out.IgnoredConnectIPs[addr] = struct{}{}
	}
	return out
}
