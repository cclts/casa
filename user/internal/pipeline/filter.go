package pipeline

import (
	"bytes"

	"github.com/cclts/casa/user/internal/ebpf"
)

// blackList suppresses noisy commands that are not useful for the current analysis flow.
var blackList = map[string]bool{
	"cpuUsage.sh": true,
	"ps":          true,
	"node":        true,
}

// Filter drops known-noisy events before they reach the more expensive user-space stages.
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
