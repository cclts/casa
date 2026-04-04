package ebpf

type Event struct {
	Pid      uint32
	Type     uint32
	Comm     [16]byte
	Filename [256]byte
}