package main

import "testing"

func TestLoadConfigRespectsEventAndSessionLogEnv(t *testing.T) {
	t.Setenv("CASA_EVENTS_LOG", "/tmp/casa-events.log")
	t.Setenv("CASA_SESSIONS_LOG", "/tmp/casa-sessions.log")
	t.Setenv("CASA_OTEL_EXPORTER_OTLP_ENDPOINT", "jaeger:4318")

	cfg := loadConfig()

	if cfg.EventLogPath != "/tmp/casa-events.log" {
		t.Fatalf("unexpected events log path: %q", cfg.EventLogPath)
	}
	if cfg.SessionLogPath != "/tmp/casa-sessions.log" {
		t.Fatalf("unexpected sessions log path: %q", cfg.SessionLogPath)
	}
	if cfg.Telemetry.Endpoint != "jaeger:4318" {
		t.Fatalf("unexpected telemetry endpoint: %q", cfg.Telemetry.Endpoint)
	}
}
