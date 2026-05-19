package main

import (
	stdcontext "context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cclts/casa/user/internal/audit"
	"github.com/cclts/casa/user/internal/context"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/ebpf"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/pipeline"
	"github.com/cclts/casa/user/internal/provider"
	"github.com/cclts/casa/user/internal/rules"
	"github.com/cclts/casa/user/internal/telemetry"
)

type Config struct {
	EventLogPath   string
	LatencyLogPath string
	SessionLogPath string
	RulePath       string
	LogPath        string
	AlertPath      string
	BPFPath        string
	PIDPath        string
	BufSize        int
	Telemetry      telemetry.Config
}

func main() {
	cfg := loadConfig()

	ctx, stop := signal.NotifyContext(stdcontext.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := writePIDFile(cfg.PIDPath); err != nil {
		log.Fatalf("write pid file: %v", err)
	}
	defer func() {
		if err := os.Remove(cfg.PIDPath); err != nil && !os.IsNotExist(err) {
			log.Printf("remove pid file failed: %v", err)
		}
	}()

	ruleEngine, err := rules.NewEngine(cfg.RulePath)
	if err != nil {
		log.Fatalf("load rule config: %v", err)
	}

	decisionEngine := decision.NewEngine(ruleEngine)
	configureHeuristics(decisionEngine.AnalysisConfig())
	pipeline.ConfigureFilters(decisionEngine.AnalysisConfig())
	providerClassifier := configureConfiguredConnectClassifier(ctx, decisionEngine.AnalysisConfig())
	traceManager, err := telemetry.NewManager(ctx, cfg.Telemetry)
	if err != nil {
		log.Fatalf("initialize telemetry: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := stdcontext.WithTimeout(stdcontext.Background(), 5*time.Second)
		defer cancel()
		if err := traceManager.Shutdown(shutdownCtx); err != nil {
			log.Printf("telemetry shutdown failed: %v", err)
		}
	}()

	stopReload := setupReload(decisionEngine, cfg.RulePath)
	defer stopReload()

	auditMonitor, err := audit.NewMonitor(cfg.EventLogPath, cfg.LatencyLogPath, cfg.SessionLogPath, cfg.LogPath, cfg.AlertPath)
	if err != nil {
		log.Fatalf("initialize audit monitor: %v", err)
	}
	defer func() {
		if err := auditMonitor.Close(); err != nil {
			log.Printf("audit monitor close failed: %v", err)
		}
	}()

	loader, err := ebpf.Load(cfg.BPFPath)
	if err != nil {
		log.Fatalf("load eBPF object: %v", err)
	}

	var closeLoaderOnce sync.Once
	closeLoader := func() {
		closeLoaderOnce.Do(func() {
			loader.Close()
		})
	}
	defer closeLoader()

	if err := loader.Attach(); err != nil {
		log.Fatalf("attach eBPF probes: %v", err)
	}

	rawEvents := make(chan ebpf.Sample, cfg.BufSize)
	events := make(chan event.Event, cfg.BufSize)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(rawEvents)

		if err := loader.ReadEvents(rawEvents); err != nil {
			log.Printf("eBPF reader stopped: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(events)

		for sample := range rawEvents {
			evt := ebpf.ToEvent(sample.Event)
			evt.Latency.RingbufReadAt = sample.RingbufReadAt
			evt.Latency.RawSendStartAt = sample.RawSendStartAt
			evt.Latency.RawRecvAt = time.Now()
			evt.Latency.NormalizeDoneAt = time.Now()
			evt.Latency.EventSendStartAt = time.Now()
			events <- evt
		}
	}()

	pipelineDone := make(chan struct{})
	go func() {
		defer close(pipelineDone)
		pipeline.Run(ctx, events, decisionEngine, auditMonitor, providerClassifier, traceManager)
	}()

	log.Println("CASA pipeline is running")
	log.Printf("rules=%s audit=%s alert=%s", cfg.RulePath, cfg.LogPath, cfg.AlertPath)

	select {
	case <-ctx.Done():
		log.Println("shutdown signal received")
		closeLoader()
		wg.Wait()
		<-pipelineDone

	case <-pipelineDone:
		log.Println("pipeline exited")
		closeLoader()
		wg.Wait()
	}
}

func loadConfig() Config {
	return Config{
		EventLogPath:   getenvFirst([]string{"CASA_EVENTS_LOG_PATH", "CASA_EVENTS_LOG"}, "user/logs/events.log"),
		LatencyLogPath: getenvFirst([]string{"CASA_LATENCY_TRACE_PATH", "CASA_LATENCY_TRACE"}, ""),
		SessionLogPath: getenvFirst([]string{"CASA_SESSIONS_LOG_PATH", "CASA_SESSIONS_LOG"}, "user/logs/sessions.log"),
		RulePath:       getenv("CASA_RULES_PATH", "user/config/rules.json"),
		LogPath:        getenv("CASA_AUDIT_LOG_PATH", "user/logs/audit.log"),
		AlertPath:      getenv("CASA_ALERT_LOG_PATH", "user/logs/alert.log"),
		BPFPath:        getenv("CASA_BPF_PATH", "ebpf/build/probes.o"),
		PIDPath:        getenv("CASA_PID_PATH", "/var/run/casa.pid"),
		BufSize:        500,
		Telemetry:      telemetry.LoadConfig(),
	}
}

func configureHeuristics(analysis rules.AnalysisConfig) {
	context.ConfigureHeuristics(context.Heuristics{
		RecentEventLimit:         analysis.RecentEventLimit,
		MaxPerProcessArtifacts:   analysis.MaxPerProcessArtifacts,
		DeepChainThreshold:       analysis.DeepChainThreshold,
		BurstOpenThreshold:       analysis.BurstOpenThreshold,
		BurstConnectThreshold:    analysis.BurstConnectThreshold,
		BurstExecThreshold:       analysis.BurstExecThreshold,
		BurstWindow:              time.Duration(analysis.BurstWindowSeconds) * time.Second,
		SensitiveHistoryWindow:   time.Duration(analysis.SensitiveHistoryWindowSecs) * time.Second,
		SuspiciousPathPatterns:   analysis.SuspiciousPathPatterns,
		SensitivePathPrefixes:    analysis.SensitivePathPrefixes,
		SensitivePathPatterns:    analysis.SensitivePathPatterns,
		ShellNames:               analysis.ShellNames,
		NetworkToolNames:         analysis.NetworkToolNames,
		InterpreterNames:         analysis.InterpreterNames,
		ContainerRuntimeNames:    analysis.ContainerRuntimeNames,
		DangerousCapabilityNames: analysis.DangerousCapabilityNames,
	})
}

func configureConfiguredConnectClassifier(ctx stdcontext.Context, analysis rules.AnalysisConfig) *provider.Classifier {
	cfg, err := provider.ConfigFromAnalysis(analysis)
	if err != nil {
		log.Printf("configured connect settings invalid: %v", err)
		return nil
	}
	if len(cfg.Targets) == 0 && len(cfg.CIDRs) == 0 {
		return nil
	}

	endpoints, err := provider.ResolveConfig(stdcontext.Background(), net.DefaultResolver, cfg)
	if err != nil {
		log.Printf("configured connect resolve failed: %v", err)
		return nil
	}
	classifier := provider.NewClassifier(endpoints)
	interval := time.Duration(analysis.ConfiguredConnectRefreshS) * time.Second
	if interval > 0 {
		provider.StartBackgroundRefresh(ctx, net.DefaultResolver, cfg, interval, classifier)
	}
	return classifier
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvFirst(keys []string, fallback string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return fallback
}

func writePIDFile(path string) error {
	pid := os.Getpid()
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", pid)), 0o644)
}

func setupReload(engine *decision.Engine, rulePath string) func() {
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})

	signal.Notify(signals, syscall.SIGHUP)

	go func() {
		defer close(done)

		for range signals {
			if err := engine.Reload(); err != nil {
				log.Printf("rule reload failed from %s: %v", rulePath, err)
				continue
			}

			configureHeuristics(engine.AnalysisConfig())
			pipeline.ConfigureFilters(engine.AnalysisConfig())

			log.Printf("rule config reloaded from %s", rulePath)
		}
	}()

	return func() {
		signal.Stop(signals)
		close(signals)
		<-done
	}
}
