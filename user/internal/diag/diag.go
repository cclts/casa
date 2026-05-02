package diag

import (
	"log"
	"os"
	"strings"
)

func Enabled() bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv("CASA_DEBUG_EVAL")))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func Logf(format string, args ...any) {
	if !Enabled() {
		return
	}
	log.Printf(format, args...)
}
