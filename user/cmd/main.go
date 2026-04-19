package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cclts/care-go/user/internal/audit"
	"github.com/cclts/care-go/user/internal/decision"
	"github.com/cclts/care-go/user/internal/ebpf"
	"github.com/cclts/care-go/user/internal/event"
	"github.com/cclts/care-go/user/internal/pipeline"
	"github.com/cclts/care-go/user/internal/rules"
)

// main wires together the runtime pipeline:
// eBPF ingestion -> event normalization -> context generation ->
// decisioning -> audit logging.
func main() {
	rulePath := os.Getenv("CARE_RULES_PATH")
	if rulePath == "" {
		rulePath = "user/config/risk_rules.json"
	}
	logPath := os.Getenv("CARE_AUDIT_LOG_PATH")
	if logPath == "" {
		logPath = "user/logs/audit.log"
	}
	alertPath := os.Getenv("CARE_ALERT_LOG_PATH")
	if alertPath == "" {
		alertPath = "user/logs/alert.log"
	}

	ruleEngine, err := rules.NewEngine(rulePath)
	if err != nil {
		log.Fatal("Failed to load rule config:", err)
	}

	decisionEngine := decision.NewEngine(ruleEngine)
	setupReload(decisionEngine, rulePath)

	auditMonitor, err := audit.NewMonitor(logPath, alertPath)
	if err != nil {
		log.Fatal("Failed to initialize audit monitor:", err)
	}
	defer auditMonitor.Close()

	// Load and prepare the compiled eBPF object file.
	loader, err := ebpf.Load("ebpf/build/probes.o")
	if err != nil {
		log.Fatal("Failed to load eBPF:", err)
	}
	defer loader.Close()

	// Attach tracepoints before starting any readers so the pipeline sees new events.
	if err := loader.Attach(); err != nil {
		log.Fatal("Failed to attach probes:", err)
	}

	// Fan raw kernel events into a buffered channel so downstream stages can decouple.
	rawEvents := make(chan ebpf.Event, 500)
	go func() {
		defer close(rawEvents)
		if err := loader.ReadEvents(rawEvents); err != nil {
			log.Println("eBPF Reader stopped:", err)
		}
	}()

	// Normalize raw structs into the internal event model used by the rest of the app.
	transformedEvents := make(chan event.Event, 500)
	go func() {
		defer close(transformedEvents)
		for e := range rawEvents {
			// Use your convert.go logic
			transformedEvents <- ebpf.ToEvent(e)
		}
	}()

	// Hand the normalized stream to the user-space analysis pipeline.
	log.Println("OpenClaw core pipeline is running...")
	log.Printf("Audit logging enabled: audit=%s alert=%s", logPath, alertPath)
	pipeline.Run(transformedEvents, decisionEngine, auditMonitor)
}

// setupReload keeps the in-memory rule engine synchronized with the on-disk rule file.
func setupReload(engine *decision.Engine, rulePath string) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)

	go func() {
		for range signals {
			if err := engine.Reload(); err != nil {
				log.Printf("rule reload failed from %s: %v", rulePath, err)
				continue
			}

			log.Printf("rule config reloaded from %s", rulePath)
		}
	}()
}
