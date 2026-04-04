package pipeline

import (
	"fmt"
	"github.com/cclts/care-go/user/internal/ebpf"
)

func Run(events <- chan ebpf.Event) {
	for e := range events {
		comm := string(e.Comm[:])
        filename := string(e.Filename[:])

        fmt.Printf("PID: %d | Comm: %s | File: %s\n", 
            e.Pid, comm, filename)
	}
}