package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func writeJSONL(file *os.File, payload any, label string) error {
	line, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	if _, err := file.Write(line); err != nil {
		return fmt.Errorf("write %s: %w", label, err)
	}

	return nil
}

// openLogFile ensures the parent directory exists before opening the target file.
func openLogFile(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
}

func syncFile(f *os.File) error {
	if f == nil {
		return nil
	}
	return f.Sync()
}
