package pipeline

import (
	"fmt"
	"net"
	"bytes"
	"github.com/cclts/care-go/user/internal/ebpf"
)

func Run(events <-chan ebpf.Event) {
    for e := range events {
        comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
        filename := string(bytes.TrimRight(e.Filename[:], "\x00"))
        
        ip := net.IPv4(byte(e.Daddr), byte(e.Daddr>>8), byte(e.Daddr>>16), byte(e.Daddr>>24))
        port := (e.Dport << 8) | (e.Dport >> 8)

        switch e.Type {
        case 0: // EventExecve
            fmt.Printf("EXECVE  | PID: %-6d | PPID: %-6d | UID: %-5d | Comm: %-16s | Path: %s\n", 
                e.Pid, e.Ppid, e.Uid, comm, filename)

        case 1: // EventOpenat
            fmt.Printf("OPENAT  | PID: %-6d | PPID: %-6d | UID: %-5d | Comm: %-16s | File: %s\n", 
                e.Pid, e.Ppid, e.Uid, comm, filename)

        case 2: // EventConnect
            fmt.Printf("CONNECT | PID: %-6d | PPID: %-6d | UID: %-5d | Comm: %-16s | Addr: %s | Port: %d\n", 
                e.Pid, e.Ppid, e.Uid, comm, ip, port)
        }
    }
}