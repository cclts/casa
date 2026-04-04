package main

import (
    "log"
    "github.com/cclts/care-go/user/internal/ebpf"
    "github.com/cclts/care-go/user/internal/pipeline"
)

func main() {
    // Load eBPF programs
    objs, err := ebpf.Load()
    if err != nil {
        log.Fatalf("failed to load ebpf: %v", err)
    }
    defer objs.Close()

    // Attach probes
    l, err := ebpf.Attach(objs)
    if err != nil {
        log.Fatalf("attach failed: %v", err)
    }
    defer l.Close()

    events := make(chan ebpf.Event, 1000)

	err = ebpf.ReadEvents(objs.Events, events)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("[+] listening for execve...")

	pipeline.Run(events)
}