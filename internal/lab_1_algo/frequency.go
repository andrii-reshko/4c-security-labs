package lab_1_algo

func LetterFrequencies(text string) map[rune]int {
	counts := make(map[rune]int, DefaultAlphabet.Size())
	for _, r := range Prepare(text) {
		if DefaultAlphabet.Contains(r) {
			counts[r]++
		}
	}
	return counts
}

type LetterCount struct {
	Letter rune
	Count  int
}

func FrequencySorted(text string) []LetterCount {
	counts := LetterFrequencies(text)
	out := make([]LetterCount, 0, len(counts))
	for _, r := range DefaultAlphabet.Runes() {
		if c, ok := counts[r]; ok {
			out = append(out, LetterCount{Letter: r, Count: c})
		}
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Count > out[j-1].Count; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
