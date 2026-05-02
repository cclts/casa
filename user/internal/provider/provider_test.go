package provider

import (
	stdcontext "context"
	"net"
	"testing"
	"time"

	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/process"
	"github.com/cclts/casa/user/internal/rules"
)

type stubResolver struct {
	hosts map[string][]net.IP
}

func (r stubResolver) LookupIP(_ stdcontext.Context, _ string, host string) ([]net.IP, error) {
	return r.hosts[host], nil
}

func TestTargetsFromAnalysisParsesURLs(t *testing.T) {
	targets, err := TargetsFromAnalysis(rules.AnalysisConfig{
		LLMProviderURLs: []string{"https://api.openai.com", "https://api.anthropic.com:8443"},
		ChannelURLs:     []string{"https://api.telegram.org"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[0].Host != "api.openai.com" || targets[0].Port != 443 {
		t.Fatalf("unexpected first target: %+v", targets[0])
	}
	if targets[1].Host != "api.anthropic.com" || targets[1].Port != 8443 {
		t.Fatalf("unexpected second target: %+v", targets[1])
	}
	if targets[2].Host != "api.telegram.org" || targets[2].Port != 443 {
		t.Fatalf("unexpected third target: %+v", targets[2])
	}
}

func TestShouldIgnoreConfiguredConnectMatchesRootDepthOnly(t *testing.T) {
	targets := []Target{{Host: "api.openai.com", Port: 443}}
	endpoints, err := ResolveTargets(stdcontext.Background(), stubResolver{
		hosts: map[string][]net.IP{
			"api.openai.com": {net.ParseIP("142.250.26.95")},
		},
	}, targets)
	if err != nil {
		t.Fatalf("resolve targets: %v", err)
	}

	classifier := NewClassifier(endpoints)
	tracker := process.NewTracker()
	tracker.Add(220536, 1487, 0, false)
	tracker.AddRoot(220536)
	tracker.Add(303060, 220536, 1, false)

	rootConnect := event.Event{
		Type: event.EventConnect,
		PID:  220536,
		PPID: 1487,
		Addr: "142.250.26.95",
		Port: 443,
	}
	if !classifier.ShouldIgnoreConfiguredConnect(rootConnect, tracker) {
		t.Fatalf("expected root-depth configured connect to be ignored")
	}

	childConnect := event.Event{
		Type: event.EventConnect,
		PID:  303060,
		PPID: 220536,
		Addr: "142.250.26.95",
		Port: 443,
	}
	if classifier.ShouldIgnoreConfiguredConnect(childConnect, tracker) {
		t.Fatalf("expected non-root-depth configured connect not to be ignored")
	}
}

func TestBackgroundRefreshReplacesEndpoints(t *testing.T) {
	targets := []Target{{Host: "api.openai.com", Port: 443}}
	classifier := NewClassifier(EndpointSet{})
	resolver := &mutableResolver{
		hosts: map[string][]net.IP{
			"api.openai.com": {net.ParseIP("142.250.26.95")},
		},
	}

	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	defer cancel()
	StartBackgroundRefresh(ctx, resolver, targets, 10*time.Millisecond, classifier)

	rootConnect := event.Event{
		Type: event.EventConnect,
		PID:  220536,
		PPID: 1487,
		Addr: "142.250.26.95",
		Port: 443,
	}

	tracker := process.NewTracker()
	tracker.Add(220536, 1487, 0, false)
	tracker.AddRoot(220536)

	deadline := time.Now().Add(250 * time.Millisecond)
	for time.Now().Before(deadline) {
		if classifier.ShouldIgnoreConfiguredConnect(rootConnect, tracker) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected background refresh to load configured endpoint")
}

type mutableResolver struct {
	hosts map[string][]net.IP
}

func (r *mutableResolver) LookupIP(_ stdcontext.Context, _ string, host string) ([]net.IP, error) {
	return r.hosts[host], nil
}
