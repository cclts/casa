package ebpf

type Event struct {
	Pid      uint32
	Ppid      uint32
	Uid      uint32
	Type     uint32
	Comm     [16]byte
	Filename [256]byte
	Daddr    uint32
    Dport    uint16
	_        [2]byte
}