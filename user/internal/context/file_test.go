package context

import "testing"

func TestDetectWriteThenExecSamePathAcrossProcessesInSession(t *testing.T) {
	state := &SessionState{
		Processes: map[uint32]*ProcessState{
			100: {
				PID: 100,
				Opens: []ObservedOpen{
					{Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0x241},
				},
			},
			101: {
				PID:      101,
				ExecPath: "/tmp/openclaw-eval/backdoor.sh",
			},
		},
	}

	if !detectWriteThenExecSamePath(state) {
		t.Fatalf("expected session-wide write-then-exec match across processes")
	}
}

func TestDetectWriteThenExecSamePathRequiresWriteIntent(t *testing.T) {
	state := &SessionState{
		Processes: map[uint32]*ProcessState{
			100: {
				PID: 100,
				Opens: []ObservedOpen{
					{Path: "/tmp/openclaw-eval/backdoor.sh", Flags: 0},
				},
			},
			101: {
				PID:      101,
				ExecPath: "/tmp/openclaw-eval/backdoor.sh",
			},
		},
	}

	if detectWriteThenExecSamePath(state) {
		t.Fatalf("expected read-only open not to trigger write-then-exec")
	}
}
