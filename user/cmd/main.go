package main

import (
    "log"
    "openclaw/internal/ebpf"
    "openclaw/internal/pipeline"
)

func main() {
    // Load eBPF programs
    objs, err := ebpf.Load()
    if err != nil {
        log.Fatalf("failed to load ebpf: %v", err)
    }
    defer objs.Close()

    // Attach probes
    err = ebpf.Attach(objs)
    if err != nil {
        log.Fatalf("attach failed: %v", err)
    }

    log.Println("[+] eBPF attached")

    // Start pipeline
    pipeline.Run(objs.Events)
}