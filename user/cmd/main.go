package main

import (
    "log"
    "bytes"
    "github.com/cclts/care-go/user/internal/ebpf"
    "github.com/cclts/care-go/user/internal/pipeline"
)

var blackList = map[string]bool{
    "cpuUsage.sh": true,
    "ps":           true,
}

func main() {
    loader, err := ebpf.Load("ebpf/build/probes.o")
	if err != nil {
		log.Fatal(err)
	}
	defer loader.Close()

	if err := loader.Attach(); err != nil {
		log.Fatal(err)
	}

	rawEvents := make(chan ebpf.Event, 500)
	filtered := make(chan ebpf.Event, 500)

	// read from kernel
	go func() {
        defer close(rawEvents)
		if err := loader.ReadEvents(rawEvents); err != nil {
			log.Println("reader stopped:", err)
		}
	}()

	// filter
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

	pipeline.Run(filtered)
}