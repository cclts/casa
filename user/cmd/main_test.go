package main

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestLoadConfigLoadsDotEnvWithoutOverridingExistingEnv(t *testing.T) {
	dir := t.TempDir()
	dotenvPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(dotenvPath, []byte("CASA_OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318/v1/traces\nCASA_OTEL_SERVICE_NAME=from-dotenv\nCASA_EVENTS_LOG=/tmp/from-dotenv.log\n"), 0o644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() {
		if chdirErr := os.Chdir(prevWD); chdirErr != nil {
			t.Fatalf("restore wd: %v", chdirErr)
		}
	}()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir tempdir: %v", err)
	}

	t.Setenv("CASA_OTEL_SERVICE_NAME", "from-env")

	cfg := loadConfig()

	if cfg.Telemetry.Endpoint != "http://collector:4318/v1/traces" {
		t.Fatalf("unexpected telemetry endpoint from .env: %q", cfg.Telemetry.Endpoint)
	}
	if cfg.Telemetry.ServiceName != "from-env" {
		t.Fatalf("expected explicit env to win, got service name %q", cfg.Telemetry.ServiceName)
	}
	if cfg.EventLogPath != "/tmp/from-dotenv.log" {
		t.Fatalf("unexpected events log path from .env: %q", cfg.EventLogPath)
	}
}
