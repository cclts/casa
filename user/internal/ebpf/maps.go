package ebpf

// Event must stay layout-compatible with the struct emitted from the kernel side.
type Event struct {
	Tgid     uint32
	Pid      uint32
	Ppid     uint32
	Uid      uint32
	Type     uint32
	Argc     uint32
	Comm     [16]byte
	Filename [128]byte
	Args     [5][64]byte
	Daddr    uint32
	Dport    uint16
}
