package shared

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrMissingText is returned by ResolveText when neither an input file nor
// positional arguments were supplied.
var ErrMissingText = errors.New("потрібно передати текст аргументом або вказати -i файл")

// Main runs a CLI command's run function against the process's own
// arguments (os.Args[1:]), printing "помилка: ..." to stderr and exiting
// with status 1 if it returns a non-nil error. It is the common main()
// body every cmd/lab_*/main.go would otherwise repeat verbatim.
func Main(run func(args []string) error) {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "помилка:", err)
		os.Exit(1)
	}
}

// ResolveText returns the text a CLI invocation should operate on: the
// contents of inFile (read via readFile) if inFile is non-empty, otherwise
// the positional arguments joined by single spaces. readFile is injected
// rather than hard-coded so this package stays free of any lab's I/O
// dependencies.
func ResolveText(inFile string, positional []string, readFile func(string) (string, error)) (string, error) {
	if inFile != "" {
		return readFile(inFile)
	}
	if len(positional) == 0 {
		return "", ErrMissingText
	}
	return strings.Join(positional, " "), nil
}
