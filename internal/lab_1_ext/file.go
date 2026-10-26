// Package lab_1_ext provides I/O helpers that sit around the core lab_1
// cryptographic package (file-based UTF-8 input/output, per section 6.1's
// "щонайменше один спосіб роботи з UTF-8 файлами" requirement) without
// being part of the cipher logic itself.
package lab_1_ext

import (
	"fmt"
	"os"
	"unicode/utf8"
)

// ReadUTF8File reads path and rejects content that is not valid UTF-8
// (section 5, "Кодування").
func ReadUTF8File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("не вдалося прочитати файл %q: %w", path, err)
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("файл %q не є коректним UTF-8", path)
	}
	return string(data), nil
}

// WriteUTF8File writes content to path using UTF-8 encoding.
func WriteUTF8File(path, content string) error {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("не вдалося записати файл %q: %w", path, err)
	}
	return nil
}
