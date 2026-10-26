// Package lab_1_ext_test holds the test suite for internal/lab_1_ext (the
// UTF-8 file I/O helpers), kept separate from the core cipher tests in
// tests/lab_1 to mirror the internal/lab_1 vs internal/lab_1_ext split.
package lab_1_ext_test

import (
	"os"
	"path/filepath"
	"testing"

	lab_1ext "4c-security-labs/internal/lab_1_ext"
)

// fixturesDir points at ./tests/fixtures, sibling of tests/lab_1 and
// tests/lab_1_ext.
const fixturesDir = "../fixtures"

func TestFileRoundTripUTF8(t *testing.T) {
	fixture := filepath.Join(fixturesDir, "sample_utf8.txt")
	content, err := lab_1ext.ReadUTF8File(fixture)
	if err != nil {
		t.Fatalf("ReadUTF8File(fixture): %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "message.txt")
	if err := lab_1ext.WriteUTF8File(path, content); err != nil {
		t.Fatalf("WriteUTF8File: %v", err)
	}

	got, err := lab_1ext.ReadUTF8File(path)
	if err != nil {
		t.Fatalf("ReadUTF8File: %v", err)
	}
	if got != content {
		t.Fatalf("ReadUTF8File = %q, want %q", got, content)
	}
}

func TestFileRejectsInvalidUTF8(t *testing.T) {
	fixture := filepath.Join(fixturesDir, "invalid_utf8.bin")
	if _, err := os.Stat(fixture); err != nil {
		t.Fatalf("fixture missing: %v", err)
	}
	if _, err := lab_1ext.ReadUTF8File(fixture); err == nil {
		t.Fatal("expected error reading invalid UTF-8 file")
	}
}
