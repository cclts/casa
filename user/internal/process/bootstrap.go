package process

import (
	"log"
	"strings"

	"github.com/cclts/care-go/user/internal/proc"
)

func BootstrapOpenClaw(tracker *Tracker) error {
	pids, err := proc.ListPIDs()
	if err != nil {
		return err
	}

	found := false

	for _, pid := range pids {
		comm, err := proc.ReadComm(pid)
		if err != nil {
			continue
		}

		exe, _ := proc.ReadExe(pid)
		if strings.Contains(strings.ToLower(comm), "openclaw") ||
			strings.Contains(strings.ToLower(exe), "openclaw") {

			ppid, err := proc.ReadPPID(pid)
			if err != nil {
				continue
			}

			tracker.Add(uint32(pid), uint32(ppid), comm)
			tracker.AddRoot(uint32(pid))

			found = true
			log.Printf("[BOOTSTRAP] Found OpenClaw: pid=%d Comm=%s\n", pid, comm)
		}
	}

	if !found {
		log.Println("openclaw not found")
	}

	return nil
}
