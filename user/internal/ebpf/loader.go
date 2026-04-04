package ebpf

import (
	"encoding/binary"
	"fmt"
	"bytes"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Objects struct {
	Events *ebpf.Map
	Prog   *ebpf.Program
}

func Load() (*Objects, error) {
	spec, err := ebpf.LoadCollectionSpec("ebpf/build/execve.o")
	if err != nil {
		return nil, err
	}

	objs := &Objects{}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	objs.Events = coll.Maps["events"]
	objs.Prog = coll.Programs["handle_execve"]

	return objs, nil
}

func Attach(objs *Objects) (link.Link, error) {
	return link.Tracepoint("syscalls", "sys_enter_execve", objs.Prog, nil)
}

func ReadEvents(events *ebpf.Map, out chan Event) error {
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return err
	}

	go func() {
		defer rd.Close()

		for {
			record, err := rd.Read()
			if err != nil {
				fmt.Println("read error:", err)
				return
			}

			var e Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &e); err != nil {
				fmt.Println("decode error:", err)
				continue
			}

			out <- e
		}
	}()

	return nil
}

func (o *Objects) Close() error {
    if o.Events != nil {
        o.Events.Close()
    }
    if o.Prog != nil {
        o.Prog.Close()
    }
    return nil
}