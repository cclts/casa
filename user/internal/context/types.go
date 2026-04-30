package context

// Context is the synthesized session-scoped view consumed by scoring, auditing,
// and user-defined CEL rules.
type Context struct {
	SessionID uint32
	TargetPID uint32

	ExecutionChains []ExecutionChainContext
	Capabilities    []CapabilityContext
	History         HistoricalContext
}

// ExecutionChainContext answers "where did this process come from?".
type ExecutionChainContext struct {
	PID                     uint32
	PPID                    uint32
	Lineage                 []LineageNode
	BinaryPath              string
	UID                     uint32
	ChainDepth              int
	SuspiciousPathExec      bool
	DeepChain               bool
	ShellInChain            bool
	NetworkToolInChain      bool
	InterpreterInChain      bool
	ContainerRuntimeInChain bool
	MemfdOrDeletedExec      bool
}

// CapabilityContext answers "what is this process allowed to do?".
type CapabilityContext struct {
	PID               uint32
	CapEffMask        uint64
	DangerousCaps     []string
	SeccompMode       int
	CapabilityUnknown bool
	HasDangerousCaps  bool
	SeccompDisabled   bool
}

// HistoricalContext answers "what has this process already done?".
type HistoricalContext struct {
	RecentSyscalls        []string
	ExecCount             int
	OpenCount             int
	ConnectCount          int
	TimeWindowSeconds     int64
	ConnectThenExec       bool
	SensitiveThenNetwork  bool
	SensitiveThenExecve   bool
	BurstConnect          bool
	BurstExec             bool
	UniqueOpenPathCount   int
	WriteThenExecSamePath bool
	OpenedDeletedPath     bool
}
