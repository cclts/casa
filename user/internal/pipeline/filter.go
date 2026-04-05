package pipeline

import (
	"bytes"
	"github.com/cclts/care-go/user/internal/ebpf"
)

var blackList = map[string]bool{
	"cpuUsage.sh": true,
	"ps":          true,
	"node":        true,
}

func Filter(rawEvents <-chan ebpf.Event) <-chan ebpf.Event {
	filtered := make(chan ebpf.Event, 500)

	go func() {
		defer close(filtered)
		for e := range rawEvents {
			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))

			if blackList[comm] {
				continue
			}

			filtered <- e
		}
	}()

	return filtered
}