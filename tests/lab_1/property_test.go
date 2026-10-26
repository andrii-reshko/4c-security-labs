package lab_1_test

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	algo "4c-security-labs/internal/lab_1_algo"
	"4c-security-labs/internal/shared"
)

// generativeIterations is how many random (key, message) pairs each
// property test tries per algorithm (section 13: "додати генеративні тести
// для випадкових коректних ключів і повідомлень").
const generativeIterations = 50

// propertyAlphabetRunes mirrors algo.DefaultAlphabet for generating random letters
// without needing an exported rune slice from the package under test.
var propertyAlphabetRunes = algo.DefaultAlphabet.Runes()

func randomLetters(rng *rand.Rand, minLen, maxLen int) string {
	n := minLen + rng.Intn(maxLen-minLen+1)
	letters := make([]rune, n)
	for i := range letters {
		letters[i] = propertyAlphabetRunes[rng.Intn(len(propertyAlphabetRunes))]
	}
	return string(letters)
}

// randomMessage builds a random message mixing alphabet letters with
// spaces, digits and punctuation, so the generative tests also exercise the
// "foreign characters are preserved" path (section 5), not just letters.
func randomMessage(rng *rand.Rand, minLen, maxLen int) string {
	extras := []rune{' ', ' ', ' ', ',', '.', '-', '0', '5', '9'} // spaces weighted higher, like real text
	n := minLen + rng.Intn(maxLen-minLen+1)
	runes := make([]rune, n)
	for i := range runes {
		if rng.Intn(5) == 0 {
			runes[i] = extras[rng.Intn(len(extras))]
		} else {
			runes[i] = propertyAlphabetRunes[rng.Intn(len(propertyAlphabetRunes))]
		}
	}
	return string(runes)
}

// randomPermutationKey returns a random permutation of 1..n as a
// space-separated key string, valid for both block and columnar ciphers.
func randomPermutationKey(rng *rand.Rand, n int) string {
	nums := make([]int, n)
	for i := range nums {
		nums[i] = i + 1
	}
	rng.Shuffle(n, func(i, j int) { nums[i], nums[j] = nums[j], nums[i] })
	parts := make([]string, n)
	for i, v := range nums {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, " ")
}

func TestPropertySubstitutionRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	c := algo.NewSubstitutionCipher("")
	for i := 0; i < generativeIterations; i++ {
		key := randomLetters(rng, 1, 15)
		msg := randomMessage(rng, 0, 80)

		if err := c.ValidateKey(key); err != nil {
			t.Fatalf("iteration %d: generated key %q failed validation: %v", i, key, err)
		}
		res, err := c.Encrypt(key, msg)
		if err != nil {
			t.Fatalf("iteration %d: Encrypt(key=%q, msg=%q): %v", i, key, msg, err)
		}
		plain, err := c.Decrypt(key, res)
		if err != nil {
			t.Fatalf("iteration %d: Decrypt: %v", i, err)
		}
		if want := shared.Prepare(msg); plain != want {
			t.Fatalf("iteration %d: round-trip(key=%q, msg=%q) = %q, want %q", i, key, msg, plain, want)
		}
	}
}

func TestPropertyVigenereRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	c := algo.NewVigenereCipher("")
	for i := 0; i < generativeIterations; i++ {
		key := randomLetters(rng, 1, 10)
		msg := randomMessage(rng, 0, 80)

		if err := c.ValidateKey(key); err != nil {
			t.Fatalf("iteration %d: generated key %q failed validation: %v", i, key, err)
		}
		res, err := c.Encrypt(key, msg)
		if err != nil {
			t.Fatalf("iteration %d: Encrypt(key=%q, msg=%q): %v", i, key, msg, err)
		}
		plain, err := c.Decrypt(key, res)
		if err != nil {
			t.Fatalf("iteration %d: Decrypt: %v", i, err)
		}
		if want := shared.Prepare(msg); plain != want {
			t.Fatalf("iteration %d: round-trip(key=%q, msg=%q) = %q, want %q", i, key, msg, plain, want)
		}
	}
}

func TestPropertyBlockPermutationRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	c := algo.NewBlockPermutationCipher("")
	for i := 0; i < generativeIterations; i++ {
		n := 2 + rng.Intn(7) // block length 2..8
		key := randomPermutationKey(rng, n)
		msg := randomMessage(rng, 0, 80)

		if err := c.ValidateKey(key); err != nil {
			t.Fatalf("iteration %d: generated key %q failed validation: %v", i, key, err)
		}
		res, err := c.Encrypt(key, msg)
		if err != nil {
			t.Fatalf("iteration %d: Encrypt(key=%q, msg=%q): %v", i, key, msg, err)
		}
		plain, err := c.Decrypt(key, res)
		if err != nil {
			t.Fatalf("iteration %d: Decrypt: %v", i, err)
		}
		if want := shared.Prepare(msg); plain != want {
			t.Fatalf("iteration %d: round-trip(key=%q, msg=%q) = %q, want %q", i, key, msg, plain, want)
		}
	}
}

func TestPropertyColumnarRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	c := algo.NewColumnarCipher("")
	for i := 0; i < generativeIterations; i++ {
		k := 2 + rng.Intn(7) // 2..8 columns
		key := randomPermutationKey(rng, k)
		msg := randomMessage(rng, 0, 80)

		if err := c.ValidateKey(key); err != nil {
			t.Fatalf("iteration %d: generated key %q failed validation: %v", i, key, err)
		}
		res, err := c.Encrypt(key, msg)
		if err != nil {
			t.Fatalf("iteration %d: Encrypt(key=%q, msg=%q): %v", i, key, msg, err)
		}
		plain, err := c.Decrypt(key, res)
		if err != nil {
			t.Fatalf("iteration %d: Decrypt: %v", i, err)
		}
		if want := shared.Prepare(msg); plain != want {
			t.Fatalf("iteration %d: round-trip(key=%q, msg=%q) = %q, want %q", i, key, msg, plain, want)
		}
	}
}

func TestPropertyHomophonicRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	c := algo.NewHomophonicCipher("")
	for i := 0; i < generativeIterations; i++ {
		seed := fmt.Sprintf("seed-%d", rng.Int63())
		msg := randomMessage(rng, 0, 80)

		res, err := c.Encrypt(seed, msg)
		if err != nil {
			t.Fatalf("iteration %d: Encrypt(seed=%q, msg=%q): %v", i, seed, msg, err)
		}
		plain, err := c.Decrypt(seed, res)
		if err != nil {
			t.Fatalf("iteration %d: Decrypt: %v", i, err)
		}
		if want := algo.PrepareWithMode(msg, algo.PrepLettersOnly); plain != want {
			t.Fatalf("iteration %d: round-trip(seed=%q, msg=%q) = %q, want %q", i, seed, msg, plain, want)
		}
	}
}
