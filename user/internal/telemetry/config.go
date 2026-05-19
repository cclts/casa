package telemetry

import (
	"os"
	"strconv"
	"strings"
)

const defaultServiceName = "casa"

// Config controls optional OpenTelemetry export.
type Config struct {
	Endpoint    string
	ServiceName string
	Insecure    bool
}

// Enabled reports whether telemetry export should be initialized.
func (c Config) Enabled() bool {
	return strings.TrimSpace(c.Endpoint) != ""
}

// Summary renders a log-friendly view of the active telemetry config.
func (c Config) Summary() string {
	if !c.Enabled() {
		return "disabled"
	}
	return "endpoint=" + c.Endpoint + " service=" + c.ServiceName + " insecure=" + strconv.FormatBool(c.Insecure)
}

// LoadConfig reads telemetry settings from CASA-specific env vars first and
// then falls back to standard OTEL env vars.
func LoadConfig() Config {
	return Config{
		Endpoint: firstEnv(
			[]string{
				"CASA_OTEL_EXPORTER_OTLP_ENDPOINT",
				"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
				"OTEL_EXPORTER_OTLP_ENDPOINT",
			},
			"",
		),
		ServiceName: firstEnv(
			[]string{
				"CASA_OTEL_SERVICE_NAME",
				"OTEL_SERVICE_NAME",
			},
			defaultServiceName,
		),
		Insecure: boolEnv(
			[]string{
				"CASA_OTEL_EXPORTER_OTLP_INSECURE",
				"OTEL_EXPORTER_OTLP_INSECURE",
			},
			true,
		),
	}
}

func firstEnv(keys []string, fallback string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return fallback
}

func boolEnv(keys []string, fallback bool) bool {
	for _, key := range keys {
		value := strings.TrimSpace(os.Getenv(key))
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseBool(value)
		if err == nil {
			return parsed
		}
	}
	return fallback
}
