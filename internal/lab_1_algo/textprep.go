package lab_1_algo

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

type PrepMode int

const (
	// PrepPreserve keeps every normalized character including spaces and punctuation
	PrepPreserve PrepMode = iota
	// PrepLettersOnly strips everything outside the base alphabet. It is
	PrepLettersOnly
)

func Prepare(text string) string {
	normalized := norm.NFC.String(text)
	return strings.ToUpper(normalized)
}

func PrepareWithMode(text string, mode PrepMode) string {
	prepared := Prepare(text)
	if mode == PrepPreserve {
		return prepared
	}

	var b strings.Builder
	b.Grow(len(prepared))
	for _, r := range prepared {
		if DefaultAlphabet.Contains(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
