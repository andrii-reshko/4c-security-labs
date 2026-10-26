package lab_1_algo

import (
	"strings"

	"4c-security-labs/internal/shared"
)

type PrepMode int

const (
	// PrepPreserve keeps every normalized character including spaces and punctuation
	PrepPreserve PrepMode = iota
	// PrepLettersOnly strips everything outside the base alphabet. It is
	PrepLettersOnly
)

func PrepareWithMode(text string, mode PrepMode) string {
	prepared := shared.Prepare(text)
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
