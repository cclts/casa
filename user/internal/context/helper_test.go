package context

import "testing"

func TestDetectOpenedDeletedPath(t *testing.T) {
	state := &SessionState{
		Processes: map[uint32]*ProcessState{
			100: {
				PID: 100,
				Opens: []ObservedOpen{
					{Path: "/tmp/payload (deleted)"},
				},
			},
		},
	}

	if !detectOpenedDeletedPath(state.snapshot()) {
		t.Fatalf("expected deleted-path open to be detected")
	}
}

func TestOpenHasWriteIntent(t *testing.T) {
	if !openHasWriteIntent(1) {
		t.Fatalf("expected O_WRONLY to count as write intent")
	}
	if openHasWriteIntent(0) {
		t.Fatalf("expected read-only flags not to count as write intent")
	}
}
