package process

import (
    "strings"

    "github.com/cclts/care-go/user/internal/proc"
)

func BootstrapOpenClaw(tracker *Tracker) error {
    pids, err := proc.ListPIDs()
    if err != nil {
        return err
    }

    for _, pid := range pids {
        comm, err := proc.ReadComm(pid)
        if err != nil {
            continue
        }

        if strings.Contains(comm, "openclaw") {
            tracker.Add(uint32(pid))
        }
    }

    return nil
}