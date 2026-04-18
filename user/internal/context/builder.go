package context

import (
	"math/bits"
	"sort"

	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/proc"
)

type Context struct {
	SessionID uint32
	TargetPID uint32

	Execution  ExecutionChainContext
	Capability CapabilityContext
	History    HistoricalContext
}

type ExecutionChainContext struct {
	Lineage        []LineageNode
	BinaryPath     string
	UID            uint32
	ChainDepth     int
	SuspiciousPath bool
}

type CapabilityContext struct {
	CapEffMask        uint64
	DangerousCaps     []string
	HasDangerousCaps  bool
	SeccompMode       int
	SeccompEnabled    bool
	CapabilityUnknown bool
}

type HistoricalContext struct {
	RecentSyscalls        []string
	ExecCount             int
	OpenCount             int
	ConnectCount          int
	ConnectThenExec       bool
	SensitiveFileThenNet  bool
	TimeWindowSeconds     int64
}

func Build(state *SessionState, targetPID uint32) Context {
	ctx := Context{
		SessionID: state.ID,
		TargetPID: targetPID,
	}

	procState := state.Processes[targetPID]
	if procState == nil {
		return ctx
	}

	ctx.Execution = buildExecutionContext(procState)
	ctx.Capability = buildCapabilityContext(targetPID)
	ctx.History = buildHistoricalContext(state, targetPID)

	return ctx
}

func buildExecutionContext(procState *ProcessState) ExecutionChainContext {
	lineage := append([]LineageNode(nil), procState.Lineage...)
	if len(lineage) == 0 {
		lineage = []LineageNode{{
			PID:  procState.PID,
			PPID: procState.PPID,
			Comm: procState.Comm,
		}}
	}

	return ExecutionChainContext{
		Lineage:        lineage,
		BinaryPath:     procState.ExecPath,
		UID:            procState.UID,
		ChainDepth:     procState.Depth,
		SuspiciousPath: isSuspiciousPath(procState.ExecPath),
	}
}

func buildCapabilityContext(pid uint32) CapabilityContext {
	mask, seccompMode, err := proc.ReadProcSecurityDetails(int(pid))
	if err != nil {
		return CapabilityContext{
			CapabilityUnknown: true,
		}
	}

	dangerous := activeDangerousCaps(mask)

	return CapabilityContext{
		CapEffMask:       mask,
		DangerousCaps:    dangerous,
		HasDangerousCaps: len(dangerous) > 0,
		SeccompMode:      seccompMode,
		SeccompEnabled:   seccompMode != 0,
	}
}

func buildHistoricalContext(state *SessionState, targetPID uint32) HistoricalContext {
	procState := state.Processes[targetPID]
	if procState == nil {
		return HistoricalContext{}
	}

	recent := make([]string, 0, len(state.RecentEvents))
	var firstEventUnix int64
	var lastEventUnix int64

	for _, evt := range state.RecentEvents {
		if evt.PID != targetPID {
			continue
		}

		recent = append(recent, evt.Type.String())

		unix := evt.Time.Unix()
		if firstEventUnix == 0 || unix < firstEventUnix {
			firstEventUnix = unix
		}
		if unix > lastEventUnix {
			lastEventUnix = unix
		}
	}

	return HistoricalContext{
		RecentSyscalls:       recent,
		ExecCount:            procState.ExecCount,
		OpenCount:            procState.OpenCount,
		ConnectCount:         procState.ConnectCount,
		ConnectThenExec:      detectConnectThenExec(state.RecentEvents, targetPID),
		SensitiveFileThenNet: detectSensitiveThenNetwork(procState),
		TimeWindowSeconds:    lastEventUnix - firstEventUnix,
	}
}

func activeDangerousCaps(mask uint64) []string {
	mapping := map[uint]int{
		proc.CAP_SYS_ADMIN:  0,
		proc.CAP_NET_ADMIN:  1,
		proc.CAP_NET_RAW:    2,
		proc.CAP_SYS_PTRACE: 3,
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

func detectConnectThenExec(events []ObservedEvent, targetPID uint32) bool {
	var seenConnect bool
	for _, evt := range events {
		if evt.PID != targetPID {
			continue
		}
		if evt.Type == event.EventConnect {
			seenConnect = true
			continue
		}
		if seenConnect && evt.Type == event.EventExecve {
			return true
		}
	}
	return false
}

func detectSensitiveThenNetwork(procState *ProcessState) bool {
	var seenSensitive bool

	for _, open := range procState.Opens {
		if isSensitivePath(open.Path) {
			seenSensitive = true
			break
		}
	}

	return seenSensitive && len(procState.Connects) > 0
}
