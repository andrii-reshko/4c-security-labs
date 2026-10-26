package lab_1_test

import (
	"sort"
	"testing"

	algo "4c-security-labs/internal/lab_1_algo"
)

// TestSubstitutionPreservesFrequencyMultiset is the formal version of
// section 13's "побудувати гістограму частот для відкритого тексту і
// шифротексту простої підстановки та пояснити подібність розподілів":
// a monoalphabetic substitution is a bijection on the alphabet, so it only
// relabels which letter carries which count — the *multiset* of counts
// (i.e. the histogram shape with the letters removed) is identical between
// plaintext and ciphertext. That is exactly why simple substitution falls
// to frequency analysis: an attacker who knows the ciphertext histogram
// shape already knows the plaintext histogram shape, and only needs to
// figure out the relabeling.
func TestSubstitutionPreservesFrequencyMultiset(t *testing.T) {
	plaintext := "ЛАБОРАТОРНА РОБОТА З КРИПТОГРАФІЇ ВИВЧАЄ ШИФРИ ПІДСТАНОВКИ ТА ПЕРЕСТАНОВКИ"
	c := algo.NewSubstitutionCipher("")
	res, err := c.Encrypt("КРИПТОГРАФІЯ", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	plainCounts := sortedCounts(algo.LetterFrequencies(plaintext))
	cipherCounts := sortedCounts(algo.LetterFrequencies(res.Text))

	if len(plainCounts) != len(cipherCounts) {
		t.Fatalf("different number of distinct letters: plaintext=%d ciphertext=%d", len(plainCounts), len(cipherCounts))
	}
	for i := range plainCounts {
		if plainCounts[i] != cipherCounts[i] {
			t.Fatalf("frequency multisets differ at rank %d: plaintext=%v ciphertext=%v", i, plainCounts, cipherCounts)
		}
	}
}

func sortedCounts(freq map[rune]int) []int {
	counts := make([]int, 0, len(freq))
	for _, c := range freq {
		counts = append(counts, c)
	}
	sort.Ints(counts)
	return counts
}
