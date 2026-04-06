package pipeline

import (
	// "fmt"
	// "net"
	// "bytes"
	"log"

	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/process"
)

func Run(events <-chan event.Event) {
	tracker := process.NewTracker()

	if err := process.BootstrapOpenClaw(tracker); err != nil {
		log.Println("bootstrap error:", err)
	}

	log.Println("bootstrap done")

	for e := range events {

		if e.Type == 0 { // EventExecve
			tracker.Propagate(e.PID, e.PPID, e.Comm)
		}

		if !tracker.Exists(e.PID) && !tracker.Exists(e.PPID) {
			continue
		}

		lineage := process.BuildLineage(int(e.PID), tracker)

		log.Printf("[TRACE] pid=%d depth=%d\n", e.PID, lineage.Depth)

		for _, n := range lineage.Nodes {
			log.Printf("  ↳ %d (%s)", n.PID, n.Comm)
		}
	}
}
