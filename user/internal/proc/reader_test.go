package proc

import (
	"strings"
	"testing"
	"time"
)

func TestParsePPIDFromStat(t *testing.T) {
	ppid, err := parsePPIDFromStat([]byte("123 (bash) S 45 1 1 0 -1 0 0 0 0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ppid != 45 {
		t.Fatalf("expected ppid 45, got %d", ppid)
	}
}

func TestParseBootTime(t *testing.T) {
	ts, err := parseBootTime([]byte("cpu 1 2 3\nbtime 1710000000\nintr 0\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ts.Equal(time.Unix(1710000000, 0)) {
		t.Fatalf("unexpected boot time: %v", ts)
	}
}

func TestParseProcSecurityDetails(t *testing.T) {
	mask, seccomp, err := parseProcSecurityDetails(strings.NewReader("Name:\tbash\nCapEff:\t0000000000002000\nSeccomp:\t2\n"), "/proc/123/status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mask != 0x2000 || seccomp != 2 {
		t.Fatalf("unexpected security details: mask=%x seccomp=%d", mask, seccomp)
	}
}

func TestFormatEventTimeZero(t *testing.T) {
	if got := FormatEventTime(time.Time{}); got != "" {
		t.Fatalf("expected zero time to format as empty string, got %q", got)
	}
}
