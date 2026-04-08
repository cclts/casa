package context

type Context struct {
	Execution ExecutionContext
	History   HistoricalContext
}

type ExecutionContext struct {
	Depth int

	SuspiciousPath  bool
	SuspiciousChain bool
	DeepChain       bool
}

type HistoricalContext struct {
	ConnectThenExec      bool
	SensitiveThenConnect bool
}

func BuildContext(s *Session) Context {

	ctx := Context{}

	// ===== Execution =====

	ctx.Execution.Depth = computeDepth(s.Root)

	if ctx.Execution.Depth > 4 {
		ctx.Execution.DeepChain = true
	}

	// 掃整棵樹
	nodes := collectNodes(s.Root)

	for _, n := range nodes {

		// suspicious path（exec 層）
		if isSuspiciousPath(n.ExecPath) {
			ctx.Execution.SuspiciousPath = true
		}
	}

	// graph pattern（不是 string）
	if matchSuspiciousChain(s.Root) {
		ctx.Execution.SuspiciousChain = true
	}

	// ===== Historical =====

	ctx.History.ConnectThenExec = detectConnectThenExec(nodes)
	ctx.History.SensitiveThenConnect = detectSensitiveThenConnect(nodes)

	return ctx
}
