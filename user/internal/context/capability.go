package context

import (
	"math/bits"
	"sort"
)

const (
	capSysAdmin  = 21
	capSysPtrace = 19
	capNetAdmin  = 12
	capNetRaw    = 13
)

// buildCapabilityContext reads the previously captured security snapshot for the process.
func buildCapabilityContext(procState *ProcessState) CapabilityContext {
	snapshot := procState.Security
	if snapshot == nil || !snapshot.Available {
		return CapabilityContext{
			CapabilityUnknown: true,
		}
	}

	dangerous := activeDangerousCaps(snapshot.CapEffMask)

	return CapabilityContext{
		CapEffMask:        snapshot.CapEffMask,
		DangerousCaps:     dangerous,
		SeccompMode:       snapshot.SeccompMode,
		HasDangerousCaps:  len(dangerous) > 0,
		SeccompDisabled:   snapshot.SeccompMode == 0,
		CapabilityUnknown: false,
	}
}

// activeDangerousCaps expands a capability mask into the subset we currently score as risky.
func activeDangerousCaps(mask uint64) []string {
	mapping := map[uint]int{
		capSysAdmin:  0,
		capNetAdmin:  1,
		capNetRaw:    2,
		capSysPtrace: 3,
	}

	names := []string{
		"CAP_SYS_ADMIN",
		"CAP_NET_ADMIN",
		"CAP_NET_RAW",
		"CAP_SYS_PTRACE",
	}

	indexes := make([]int, 0, bits.OnesCount64(mask))
	for bit, idx := range mapping {
		if mask&(uint64(1)<<bit) != 0 {
			indexes = append(indexes, idx)
		}
	}

	sort.Ints(indexes)

	out := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, names[idx])
	}

	return out
}
