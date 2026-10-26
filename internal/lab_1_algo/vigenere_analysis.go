package lab_1_algo

import "sort"

// expectedICUkrainian is a rough, illustrative index-of-coincidence baseline
// for natural Ukrainian text over the 33-letter base alphabet. It is not a
// precise corpus-derived constant — it only needs to sit clearly above the
// ~1/33 ≈ 0.0303 one would see for uniformly random letters, which is what
// lets EstimateVigenereKeyLengthByIC tell "this coset still looks like
// Vigenere-shifted plaintext" apart from "this coset looks random".
const expectedICUkrainian = 0.0575

// KasiskiCandidates implements the repeated-substring ("Kasiski") method of
// section 13: it finds every repeated substring of at least minLen letters
// in the letters-only-prepared ciphertext, measures the distances between
// repeats, and ranks candidate key lengths from 2 to maxLen by how many of
// those distances they evenly divide — a key length that is the true period
// divides most repeat distances, since a repeated plaintext n-gram only
// re-aligns with the same key letters when the distance is a multiple of
// the key length. Returned candidates are ordered from most to least
// likely.
func KasiskiCandidates(ciphertext string, minLen, maxLen int) []int {
	letters := []rune(PrepareWithMode(ciphertext, PrepLettersOnly))

	positions := make(map[string][]int)
	for i := 0; i+minLen <= len(letters); i++ {
		gram := string(letters[i : i+minLen])
		positions[gram] = append(positions[gram], i)
	}

	votes := make(map[int]int)
	for _, idxs := range positions {
		if len(idxs) < 2 {
			continue
		}
		for i := 1; i < len(idxs); i++ {
			distance := idxs[i] - idxs[0]
			for length := 2; length <= maxLen; length++ {
				if distance%length == 0 {
					votes[length]++
				}
			}
		}
	}

	type candidate struct{ length, votes int }
	candidates := make([]candidate, 0, len(votes))
	for length, v := range votes {
		candidates = append(candidates, candidate{length, v})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].votes != candidates[j].votes {
			return candidates[i].votes > candidates[j].votes
		}
		return candidates[i].length < candidates[j].length
	})

	out := make([]int, len(candidates))
	for i, c := range candidates {
		out[i] = c.length
	}
	return out
}

// indexOfCoincidence computes the index of coincidence of a sequence of
// base-alphabet indices (0..m-1): the probability that two letters drawn at
// random (without replacement) from the sequence are equal.
func indexOfCoincidence(indices []int) float64 {
	n := len(indices)
	if n < 2 {
		return 0
	}
	counts := make([]int, DefaultAlphabet.Size())
	for _, idx := range indices {
		counts[idx]++
	}
	sum := 0.0
	for _, c := range counts {
		sum += float64(c) * float64(c-1)
	}
	return sum / (float64(n) * float64(n-1))
}

// elevatedICThreshold sits halfway between the IC of uniformly random
// letters over the 33-letter alphabet (1/33 ≈ 0.0303) and
// expectedICUkrainian: an average coset IC above it looks like natural text,
// below it looks like a mix of several key letters.
var elevatedICThreshold = (1.0/float64(DefaultAlphabet.Size()) + expectedICUkrainian) / 2

// EstimateVigenereKeyLengthByIC implements the index-of-coincidence method
// of section 13 ("...або індексу збігів"): for every candidate length L
// from 1 to maxLen, it splits the letters-only-prepared ciphertext into L
// cosets (letters L apart, one per key position) and averages their index
// of coincidence. A coset enciphered under a single, fixed key letter is
// just a shifted copy of natural-language text, so its IC stays close to
// expectedICUkrainian; a coset mixing several key letters behaves like
// uniformly random letters, with IC close to 1/33.
//
// Every exact multiple of the true key length also produces an elevated
// average IC (each of its cosets is itself a subsequence of a single
// true-period coset), so the smallest length clearing elevatedICThreshold —
// not the one with the single highest score — is returned as the best
// estimate; if none clears it, the highest-scoring length is used as a
// fallback. Every candidate's score is returned alongside for inspection.
func EstimateVigenereKeyLengthByIC(ciphertext string, maxLen int) (bestLength int, scores []float64) {
	letters := []rune(PrepareWithMode(ciphertext, PrepLettersOnly))
	indices := make([]int, len(letters))
	for i, r := range letters {
		idx, _ := DefaultAlphabet.IndexOf(r)
		indices[i] = idx
	}

	scores = make([]float64, maxLen)
	for length := 1; length <= maxLen; length++ {
		var cosetSum float64
		for start := 0; start < length; start++ {
			var coset []int
			for i := start; i < len(indices); i += length {
				coset = append(coset, indices[i])
			}
			cosetSum += indexOfCoincidence(coset)
		}
		scores[length-1] = cosetSum / float64(length)
	}

	for length, avg := range scores {
		if avg >= elevatedICThreshold {
			return length + 1, scores // smallest length clearing the threshold
		}
	}

	bestLength, bestScore := 1, scores[0]
	for i, avg := range scores {
		if avg > bestScore {
			bestLength, bestScore = i+1, avg
		}
	}
	return bestLength, scores
}
