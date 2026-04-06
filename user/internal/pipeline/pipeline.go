package pipeline

import (
	// "net"
	// "bytes"
	"log"
	"strings"

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

		log.Printf("[%s] (PID: %d, Depth: %d)", e.Type, e.PID, lineage.Depth)

		switch e.Type {
		case 0:
			fullArgs := ""
			if len(e.Args) > 0 {
				fullArgs = strings.Join(e.Args, " ")
			}

			log.Printf("  ➤ Exec: %s", e.Path)
			if fullArgs != "" {
				log.Printf("  ➤ Args: %s", fullArgs)
			}

		case 1:
			log.Printf("  ➤ Open: %s", e.Path)
		case 2:
			log.Printf("  ➤ Connect: %s:%d", e.Addr, e.Port)
		}
		for i, n := range lineage.Nodes {
			prefix := "  ↳"
			if i == 0 {
				prefix = "  [Target]"
			}
			indent := strings.Repeat("    ", i)
			log.Printf("%s%s %d (%s)", indent, prefix, n.PID, n.Comm)
		}
	}
}
