package lab_1_test

import (
	"testing"

	algo "4c-security-labs/internal/lab_1_algo"
)

// TestHomophoneTableCoversAllCodesExactlyOnce verifies the apportionment
// invariants the cipher depends on: every one of the 100 two-digit codes is
// assigned to exactly one letter, and every one of the 33 letters gets at
// least one code (so encryption never panics on an empty option list).
func TestHomophoneTableCoversAllCodesExactlyOnce(t *testing.T) {
	total := 0
	for _, r := range algo.DefaultAlphabet.Runes() {
		count := algo.HomophoneCodeCount(r)
		if count < 1 {
			t.Fatalf("letter %q has no homophone codes", r)
		}
		total += count
	}
	if total != 100 {
		t.Fatalf("total homophone codes = %d, want 100", total)
	}
}
