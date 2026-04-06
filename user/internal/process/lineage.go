package process

import (
    "github.com/cclts/care-go/user/internal/proc"
)

type Node struct {
    PID  int
    PPID int
    Comm string
    Path string
    UID  int
}

type Lineage struct {
    Nodes []Node
    Depth int
}

const MaxDepth = 4

func BuildLineage(pid int, tracker *Tracker) Lineage {
    var nodes []Node
    current := pid

    for i := 0; i < MaxDepth; i++ {
		// use tracker first
        if info, ok := tracker.GetInfo(uint32(current)); ok {
            nodes = append(nodes, Node{
                PID:  current,
                PPID: int(info.PPID),
                Comm: info.Comm,
            })

			if tracker.IsRoot(uint32(current)) {
                break
            }

            current = int(info.PPID)

            continue
        }

		// fallback to /proc
        comm, err := proc.ReadComm(current)
        if err != nil {
            break
        }

        ppid, err := proc.ReadPPID(current)
        if err != nil {
            break
        }

        nodes = append(nodes, Node{
            PID:  current,
            PPID: ppid,
            Comm: comm,
        })

        if tracker.IsRoot(uint32(current)) {
			break
		}

        current = ppid
    }

    return Lineage{
        Nodes: nodes,
        Depth: len(nodes),
    }
}