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

func BuildLineage(pid int) Lineage {
    var nodes []Node

    current := pid

    for i := 0; i < MaxDepth; i++ {
        comm, err := proc.ReadComm(current)
        if err != nil {
            break
        }

        ppid, err := proc.ReadPPID(current)
        if err != nil {
            break
        }

        path, _ := proc.ReadExe(current) // optional（下面補）

        nodes = append(nodes, Node{
            PID:  current,
            PPID: ppid,
            Comm: comm,
            Path: path,
        })

        if ppid <= 1 {
            break
        }

        current = ppid
    }

    return Lineage{
        Nodes: nodes,
        Depth: len(nodes),
    }
}