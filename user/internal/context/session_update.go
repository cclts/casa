package context

import (
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
)

func applyCommonProcessMetadata(procState *ProcessState, e event.Event) {
	if procState == nil {
		return
	}
	procState.PPID = e.PPID
	procState.UID = e.UID
	if procState.Comm == "" {
		procState.Comm = e.Comm
	}
	procState.LastSeen = e.Time
}

func applyExecveToProcess(session *SessionState, procState *ProcessState, lineage process.Lineage, securityStore *process.SecurityStore, e event.Event) {
	if procState == nil {
		return
	}
	depth := lineageDepth(lineage)
	procState.ExecPath = e.Path
	procState.Comm = basenameFromPath(e.Path)
	procState.Args = append([]string(nil), e.Args...)
	procState.LineageDepth = depth
	procState.Lineage = rebuildLineage(session, procState, lineage)
	procState.ExitTime = time.Time{}
	if securityStore != nil {
		if snapshot, ok := securityStore.Get(e.PID); ok {
			procState.Security = snapshot
		}
	}
}

func applyOpenatToProcess(procState *ProcessState, e event.Event) {
	if procState == nil {
		return
	}
	procState.Opens = append(procState.Opens, ObservedOpen{
		Path:  e.Path,
		Flags: e.Flags,
		Mode:  e.Mode,
		Time:  e.Time,
	})
	procState.Opens = trimOpenEvents(procState.Opens)
}

func applyConnectToProcess(procState *ProcessState, e event.Event) {
	if procState == nil {
		return
	}
	procState.Connects = append(procState.Connects, ObservedConnect{
		Endpoint: Endpoint{
			Addr: e.Addr,
			Port: e.Port,
		},
		Time: e.Time,
	})
	procState.Connects = trimConnectEvents(procState.Connects)
}

func applyExitToProcess(procState *ProcessState, e event.Event) {
	if procState == nil {
		return
	}
	if e.PID != e.TID {
		return
	}
	procState.ExitTime = e.Time
}

func appendRecentEvent(session *SessionState, e event.Event, limit int) {
	if session == nil {
		return
	}
	session.RecentEvents = append(session.RecentEvents, ObservedEvent{
		Type:  e.Type,
		PID:   e.PID,
		Path:  e.Path,
		Flags: e.Flags,
		Mode:  e.Mode,
		Addr:  e.Addr,
		Port:  e.Port,
		Time:  e.Time,
	})
	session.RecentEvents = trimRecentEvents(session.RecentEvents, limit)
}

func lineageDepth(lineage process.Lineage) int {
	if len(lineage.Nodes) == 0 {
		return 0
	}
	return len(lineage.Nodes) - 1
}

// rebuildLineage converts the process package's lineage model into the context-local shape.
func rebuildLineage(session *SessionState, procRecord *ProcessState, lineage process.Lineage) []LineageNode {
	if len(lineage.Nodes) == 0 {
		return nil
	}

	out := make([]LineageNode, 0, len(lineage.Nodes))
	for _, n := range lineage.Nodes {
		comm := ""
		switch {
		case procRecord != nil && n.PID == procRecord.PID:
			if procRecord.ExecPath != "" {
				comm = basenameFromPath(procRecord.ExecPath)
			} else {
				comm = procRecord.Comm
			}
		case session != nil:
			if ancestor := session.Processes[n.PID]; ancestor != nil {
				if ancestor.ExecPath != "" {
					comm = basenameFromPath(ancestor.ExecPath)
				} else {
					comm = ancestor.Comm
				}
			}
		}

		out = append(out, LineageNode{
			PID:  n.PID,
			PPID: n.PPID,
			Comm: comm,
		})
	}
	return out
}
