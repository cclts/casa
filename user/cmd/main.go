package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cclts/casa/user/internal/audit"
	"github.com/cclts/casa/user/internal/decision"
	"github.com/cclts/casa/user/internal/ebpf"
	"github.com/cclts/casa/user/internal/event"
	"github.com/cclts/casa/user/internal/pipeline"
	"github.com/cclts/casa/user/internal/rules"
)

type Config struct {
	RulePath  string
	LogPath   string
	AlertPath string
	BPFPath   string
	BufSize   int
}

func main() {
	cfg := loadConfig()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ruleEngine, err := rules.NewEngine(cfg.RulePath)
	if err != nil {
		log.Fatalf("load rule config: %v", err)
	}

	decisionEngine := decision.NewEngine(ruleEngine)

	stopReload := setupReload(decisionEngine, cfg.RulePath)
	defer stopReload()

	auditMonitor, err := audit.NewMonitor(cfg.LogPath, cfg.AlertPath)
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

	rawEvents := make(chan ebpf.Event, cfg.BufSize)
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

		for raw := range rawEvents {
			events <- ebpf.ToEvent(raw)
		}
	}()

	pipelineDone := make(chan struct{})
	go func() {
		defer close(pipelineDone)
		pipeline.Run(events, decisionEngine, auditMonitor)
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
		RulePath:  getenv("CASA_RULES_PATH", "user/config/risk_rules.json"),
		LogPath:   getenv("CASA_AUDIT_LOG_PATH", "user/logs/audit.log"),
		AlertPath: getenv("CASA_ALERT_LOG_PATH", "user/logs/alert.log"),
		BPFPath:   getenv("CASA_BPF_PATH", "ebpf/build/probes.o"),
		BufSize:   500,
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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

			log.Printf("rule config reloaded from %s", rulePath)
		}
	}()

	return func() {
		signal.Stop(signals)
		close(signals)
		<-done
	}
}
