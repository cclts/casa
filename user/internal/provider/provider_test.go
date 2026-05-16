package provider

import (
	stdcontext "context"
	"net"
	"net/netip"
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

func TestConfigFromAnalysisParsesURLsAndCIDRs(t *testing.T) {
	cfg, err := ConfigFromAnalysis(rules.AnalysisConfig{
		LLMProviderURLs: []string{"https://api.openai.com", "https://api.anthropic.com:8443"},
		ChannelURLs:     []string{"https://api.telegram.org"},
		KnownCIDRs:      []string{"149.154.164.0/22"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(cfg.Targets))
	}
	if cfg.Targets[0].Host != "api.openai.com" || cfg.Targets[0].Port != 443 {
		t.Fatalf("unexpected first target: %+v", cfg.Targets[0])
	}
	if cfg.Targets[1].Host != "api.anthropic.com" || cfg.Targets[1].Port != 8443 {
		t.Fatalf("unexpected second target: %+v", cfg.Targets[1])
	}
	if cfg.Targets[2].Host != "api.telegram.org" || cfg.Targets[2].Port != 443 {
		t.Fatalf("unexpected third target: %+v", cfg.Targets[2])
	}
	if len(cfg.CIDRs) != 1 || cfg.CIDRs[0].String() != "149.154.164.0/22" {
		t.Fatalf("unexpected cidrs: %+v", cfg.CIDRs)
	}
}

func TestShouldIgnoreConfiguredConnectMatchesRootDepthOnly(t *testing.T) {
	cfg := Config{Targets: []Target{{Host: "api.openai.com", Port: 443}}}
	endpoints, err := ResolveConfig(stdcontext.Background(), stubResolver{
		hosts: map[string][]net.IP{
			"api.openai.com": {net.ParseIP("142.250.26.95")},
		},
	}, cfg)
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

func TestShouldIgnoreConfiguredConnectAllowsOpenClawRuntimeChildren(t *testing.T) {
	cfg := Config{Targets: []Target{{Host: "api.openai.com", Port: 443}}}
	endpoints, err := ResolveConfig(stdcontext.Background(), stubResolver{
		hosts: map[string][]net.IP{
			"api.openai.com": {net.ParseIP("142.250.26.95")},
		},
	}, cfg)
	if err != nil {
		t.Fatalf("resolve targets: %v", err)
	}

	classifier := NewClassifier(endpoints)
	tracker := process.NewTracker()
	tracker.Add(220536, 1487, 0, false)
	tracker.AddRoot(220536)
	tracker.Add(303060, 220536, 1, false)

	connect := event.Event{
		Type: event.EventConnect,
		PID:  303060,
		PPID: 220536,
		Comm: "openclaw-gateway",
		Addr: "142.250.26.95",
		Port: 443,
	}
	if !classifier.ShouldIgnoreConfiguredConnect(connect, tracker) {
		t.Fatalf("expected configured connect from openclaw runtime child to be ignored")
	}
}

func TestBackgroundRefreshReplacesEndpoints(t *testing.T) {
	cfg := Config{Targets: []Target{{Host: "api.openai.com", Port: 443}}}
	classifier := NewClassifier(EndpointSet{})
	resolver := &mutableResolver{
		hosts: map[string][]net.IP{
			"api.openai.com": {net.ParseIP("142.250.26.95")},
		},
	}

	ctx, cancel := stdcontext.WithCancel(stdcontext.Background())
	defer cancel()
	StartBackgroundRefresh(ctx, resolver, cfg, 10*time.Millisecond, classifier)

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

func TestCIDRMatchIgnoresConfiguredConnect(t *testing.T) {
	classifier := NewClassifier(EndpointSet{
		prefixes: mustPrefixes(t, "149.154.164.0/22"),
	})
	tracker := process.NewTracker()
	tracker.Add(220536, 1487, 0, false)
	tracker.AddRoot(220536)

	connect := event.Event{
		Type: event.EventConnect,
		PID:  220536,
		PPID: 1487,
		Addr: "149.154.167.220",
		Port: 443,
	}
	if !classifier.ShouldIgnoreConfiguredConnect(connect, tracker) {
		t.Fatalf("expected cidr-backed configured connect to be ignored")
	}
}

type mutableResolver struct {
	hosts map[string][]net.IP
}

func (r *mutableResolver) LookupIP(_ stdcontext.Context, _ string, host string) ([]net.IP, error) {
	return r.hosts[host], nil
}

func mustPrefixes(t *testing.T, raw ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(raw))
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			t.Fatalf("parse cidr %q: %v", value, err)
		}
		out = append(out, prefix.Masked())
	}
	return out
}
