package main

import (
    "log"
    "github.com/cclts/care-go/user/internal/ebpf"
    "github.com/cclts/care-go/user/internal/pipeline"
)

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

    go func() {
        defer close(rawEvents)
        if err := loader.ReadEvents(rawEvents); err != nil {
            log.Println("Reader stopped:", err)
        }
    }()

    filteredEvents := pipeline.Filter(rawEvents)
    
    pipeline.Run(filteredEvents)
}