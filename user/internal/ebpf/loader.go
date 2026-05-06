package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// bpfObjects mirrors the maps and programs exported by the compiled eBPF object.
type bpfObjects struct {
	Events      *ebpf.Map     `ebpf:"events"`
	ExecveProg  *ebpf.Program `ebpf:"handle_execve"`
	OpenatProg  *ebpf.Program `ebpf:"handle_openat"`
	ConnectProg *ebpf.Program `ebpf:"handle_connect"`
	ExitProg    *ebpf.Program `ebpf:"handle_exit"`
}

// Loader owns the lifecycle of the eBPF collection, links, and ring buffer reader.
type Loader struct {
	objs  bpfObjects
	rd    *ringbuf.Reader
	links []link.Link
}

// Load opens the compiled object, loads maps/programs, and prepares the ring buffer reader.
func Load(path string) (*Loader, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, err
	}

	return &Loader{
		objs: objs,
		rd:   rd,
	}, nil
}

// Attach connects each probe program to the corresponding kernel tracepoint.
func (l *Loader) Attach() error {
	progs := []struct {
		name string
		hook string
		p    *ebpf.Program
	}{
		{"syscalls", "sys_enter_execve", l.objs.ExecveProg},
		{"syscalls", "sys_enter_openat", l.objs.OpenatProg},
		{"syscalls", "sys_enter_connect", l.objs.ConnectProg},
		{"sched", "sched_process_exit", l.objs.ExitProg},
	}

	for _, tp := range progs {
		if tp.p == nil {
			return fmt.Errorf("program %s not found", tp.hook)
		}
		lnk, err := link.Tracepoint(tp.name, tp.hook, tp.p, nil)
		if err != nil {
			return fmt.Errorf("failed to attach %s: %w", tp.hook, err)
		}
		l.links = append(l.links, lnk)
	}
	return nil
}

// ReadEvents continuously decodes ring buffer samples into strongly typed Go structs.
func (l *Loader) ReadEvents(out chan<- Event) error {
	for {
		record, err := l.rd.Read()
		if err != nil {
			return err
		}

		var e Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}

		out <- e
	}
}

// Close tears down tracepoint links, the ring buffer reader, and loaded eBPF objects.
func (l *Loader) Close() {
	for _, link := range l.links {
		if link != nil {
			link.Close()
		}
	}
	if l.rd != nil {
		l.rd.Close()
	}
	if l.objs.Events != nil {
		l.objs.Events.Close()
	}
	if l.objs.ExecveProg != nil {
		l.objs.ExecveProg.Close()
	}
	if l.objs.OpenatProg != nil {
		l.objs.OpenatProg.Close()
	}
	if l.objs.ConnectProg != nil {
		l.objs.ConnectProg.Close()
	}
	if l.objs.ExitProg != nil {
		l.objs.ExitProg.Close()
	}
}
