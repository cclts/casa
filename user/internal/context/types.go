package context

// Context is the synthesized per-process view consumed by scoring, auditing,
// and user-defined CEL rules.
type Context struct {
	SessionID uint32
	TargetPID uint32

	Execution  ExecutionContext
	Capability CapabilityContext
	History    HistoricalContext
	File       FileContext
}

// ExecutionContext answers "where did this process come from?".
type ExecutionContext struct {
	Lineage               []LineageNode
	BinaryPath            string
	UID                   uint32
	ChainDepth            int
	SuspiciousPathExec    bool
	DeepChain             bool
	ShellInChain          bool
	CurlWgetInChain       bool
	InterpreterInChain    bool
	ContainerRuntimeInChain bool
	MemfdOrDeletedExec    bool
}

// CapabilityContext answers "what is this process allowed to do?".
type CapabilityContext struct {
	CapEffMask        uint64
	DangerousCaps     []string
	SeccompMode       int
	CapabilityUnknown bool
	HasDangerousCaps  bool
	SeccompDisabled   bool
}

// HistoricalContext answers "what has this process already done?".
type HistoricalContext struct {
	RecentSyscalls      []string
	ExecCount           int
	OpenCount           int
	ConnectCount        int
	TimeWindowSeconds   int64
	ConnectThenExec     bool
	SensitiveThenNetwork bool
	SensitiveThenExecve bool
	BurstConnect        bool
	BurstExec           bool
	UniqueOpenPathCount int
}

// FileContext answers "what path-centric behaviors happened in this process?".
type FileContext struct {
	WriteThenExecSamePath bool
	OpenedDeletedPath     bool
}
