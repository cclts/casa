package telemetry

import "testing"

func TestLoadConfigPrefersCasaEnv(t *testing.T) {
	t.Setenv("CASA_OTEL_EXPORTER_OTLP_ENDPOINT", "jaeger:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "ignored:4318")
	t.Setenv("CASA_OTEL_SERVICE_NAME", "casa-dev")
	t.Setenv("CASA_OTEL_EXPORTER_OTLP_INSECURE", "false")

	cfg := LoadConfig()

	if cfg.Endpoint != "jaeger:4318" {
		t.Fatalf("unexpected endpoint: %q", cfg.Endpoint)
	}
	if cfg.ServiceName != "casa-dev" {
		t.Fatalf("unexpected service name: %q", cfg.ServiceName)
	}
	if cfg.Insecure {
		t.Fatalf("expected insecure=false")
	}
}

func TestLoadConfigFallsBackToOtelEnv(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "collector:4318")
	t.Setenv("OTEL_SERVICE_NAME", "otel-service")

	cfg := LoadConfig()

	if cfg.Endpoint != "collector:4318" {
		t.Fatalf("unexpected endpoint: %q", cfg.Endpoint)
	}
	if cfg.ServiceName != "otel-service" {
		t.Fatalf("unexpected service name: %q", cfg.ServiceName)
	}
	if !cfg.Insecure {
		t.Fatalf("expected insecure default true")
	}
}
