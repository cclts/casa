package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func writeJSONL(file *os.File, payload any, label string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return err
	}

	if _, err := file.Write(buf.Bytes()); err != nil {
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
