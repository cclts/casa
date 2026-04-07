package main

import (
	"log"

	"github.com/cclts/care-go/user/internal/ebpf"
	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/pipeline"
)

func main() {
	// 1. Initialize eBPF loader
	loader, err := ebpf.Load("ebpf/build/probes.o")
	if err != nil {
		log.Fatal("Failed to load eBPF:", err)
	}
	defer loader.Close()

	// 2. Attach probes to kernel tracepoints
	if err := loader.Attach(); err != nil {
		log.Fatal("Failed to attach probes:", err)
	}

	// 3. Setup raw event channel (direct from kernel)
	rawEvents := make(chan ebpf.Event, 500)

	// 4. Start kernel event reader
	go func() {
		defer close(rawEvents)
		if err := loader.ReadEvents(rawEvents); err != nil {
			log.Println("eBPF Reader stopped:", err)
		}
	}()

	// 5. Transform Stage: Convert ebpf.Event to event.Event
	transformedEvents := make(chan event.Event, 500)
	go func() {
		defer close(transformedEvents)
		for e := range rawEvents {
			// Use your convert.go logic
			transformedEvents <- ebpf.ToEvent(e)
		}
	}()

	// 6. Hand over to the final pipeline runner (with Tracker & Lineage)
	log.Println("OpenClaw core pipeline is running...")
	pipeline.Run(transformedEvents)
}
