package lab_1_algo

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	mrand "math/rand"
	"strings"
)

// homophoneCodeSpace is the number of two-digit codes ("00".."99") shared
// out among the 33 letters (section 4.3: a frequent letter gets several
// possible codes; one is picked at random on every encryption).
const homophoneCodeSpace = 100

// homophoneWeights are illustrative, approximate relative frequencies of
// each base-alphabet letter in Ukrainian text, in Alphabet order. They are
// not derived from a corpus — they only need to be roughly realistic enough
// to give common letters (О, А, Н, И, Т...) visibly more homophones than
// rare ones (Ф, Ґ, Щ...), which is the whole point of the exercise.
var homophoneWeights = []int{
	78, 17, 53, 20, 1, 30, 56, 6, 10, 24, // А Б В Г Ґ Д Е Є Ж З
	63, 54, 4, 14, 35, 40, 30, 69, 93, 29, // И І Ї Й К Л М Н О П
	43, 42, 60, 32, 2, 10, 6, 13, 6, 3, // Р С Т У Ф Х Ц Ч Ш Щ
	17, 7, 22, // Ь Ю Я
}

// HomophonicCipher implements the homophonic (proportional) substitution
// from section 4.3. It is an additional-level cipher (section 13), not one
// of the four mandatory algorithms, but is dispatched through the same
// Cipher/CipherService machinery as the rest.
type HomophonicCipher struct {
	seedKey       string
	codesByLetter map[rune][]string
	letterByCode  map[string]rune
}

// NewHomophonicCipher constructs the homophonic cipher. seedKey doubles as
// the "key": a non-empty value seeds a deterministic PRNG so encryption is
// reproducible (section 4.3: "для відтворюваних тестів генератор
// випадкових значень запускають із явно заданим тестовим параметром");
// an empty seedKey falls back to the system CSPRNG for an unpredictable,
// demonstration-grade choice of homophone on every call.
func NewHomophonicCipher(seedKey string) *HomophonicCipher {
	codesByLetter, letterByCode := buildHomophoneTables()
	return &HomophonicCipher{
		seedKey:       seedKey,
		codesByLetter: codesByLetter,
		letterByCode:  letterByCode,
	}
}

func (c *HomophonicCipher) Algorithm() Algorithm {
	return AlgorithmHomophonic
}

func (c *HomophonicCipher) DefaultKey() string {
	return c.seedKey
}

// ValidateKey always accepts, including the empty string: the "key" here is
// only an optional reproducibility seed, not a secret that gates the table
// (the homophone table itself is fixed), so there is nothing to reject.
func (c *HomophonicCipher) ValidateKey(string) error {
	return nil
}

// Encrypt replaces every letter of the letters-only-prepared text with one
// of its homophone codes, chosen at random. Non-letters are not supported
// (the ciphertext is a sequence of space-separated two-digit codes, so
// there is no natural slot for punctuation or digits) — this mirrors the
// "letters only" compatibility mode already used for the historical block
// permutation example.
func (c *HomophonicCipher) Encrypt(key, plaintext string) (Result, error) {
	rng, err := rngFromSeed(key)
	if err != nil {
		return Result{}, err
	}

	prepared := PrepareWithMode(plaintext, PrepLettersOnly)
	codes := make([]string, 0, len(prepared))
	for _, r := range prepared {
		options := c.codesByLetter[r]
		codes = append(codes, options[rng.Intn(len(options))])
	}
	return Result{Text: strings.Join(codes, " ")}, nil
}

// Decrypt maps each space-separated code back to its letter. Decryption
// does not depend on the seed: the code-to-letter mapping is fixed, only
// which code was *chosen* during encryption was random.
func (c *HomophonicCipher) Decrypt(_ string, in Result) (string, error) {
	fields := strings.Fields(in.Text)
	out := make([]rune, 0, len(fields))
	for _, f := range fields {
		r, ok := c.letterByCode[f]
		if !ok {
			return "", fmt.Errorf("%w: невідомий код гомофонної підстановки %q", ErrUnsupportedRune, f)
		}
		out = append(out, r)
	}
	return string(out), nil
}

// HomophoneCodeCount returns how many two-digit homophone codes the fixed
// table assigns to letter (0 if letter is outside the base alphabet). It
// exists mainly so tests can verify common letters get more codes than rare
// ones without re-deriving the table themselves.
func HomophoneCodeCount(letter rune) int {
	codesByLetter, _ := buildHomophoneTables()
	return len(codesByLetter[letter])
}

// buildHomophoneTables apportions the 100 two-digit codes among the 33
// letters proportionally to homophoneWeights (largest-remainder method,
// every letter guaranteed at least one code) and assigns them as
// contiguous, zero-padded ranges in alphabet order.
func buildHomophoneTables() (map[rune][]string, map[string]rune) {
	counts := apportion(homophoneWeights, homophoneCodeSpace, DefaultAlphabet.Size())

	codesByLetter := make(map[rune][]string, DefaultAlphabet.Size())
	letterByCode := make(map[string]rune, homophoneCodeSpace)

	next := 0
	for i, r := range DefaultAlphabet.Runes() {
		codes := make([]string, counts[i])
		for j := range codes {
			code := fmt.Sprintf("%02d", next)
			codes[j] = code
			letterByCode[code] = r
			next++
		}
		codesByLetter[r] = codes
	}
	return codesByLetter, letterByCode
}

// apportion distributes total indivisible units among n weighted buckets
// using the largest-remainder (Hamilton) method, after first reserving one
// unit per bucket so every bucket gets at least 1. Requires total >= n.
func apportion(weights []int, total, n int) []int {
	counts := make([]int, n)
	for i := range counts {
		counts[i] = 1
	}
	remaining := total - n

	sum := 0
	for _, w := range weights {
		sum += w
	}

	type share struct {
		index     int
		whole     int
		remainder float64
	}
	shares := make([]share, n)
	allocated := 0
	for i, w := range weights {
		exact := float64(w) / float64(sum) * float64(remaining)
		whole := int(exact)
		shares[i] = share{index: i, whole: whole, remainder: exact - float64(whole)}
		counts[i] += whole
		allocated += whole
	}

	// Distribute the leftover (remaining - allocated, always < n) one unit
	// at a time to the buckets with the largest fractional remainder.
	leftover := remaining - allocated
	for leftover > 0 {
		best := -1
		for i, s := range shares {
			if s.remainder < 0 {
				continue // already spent
			}
			if best == -1 || shares[i].remainder > shares[best].remainder {
				best = i
			}
		}
		counts[best]++
		shares[best].remainder = -1 // mark as spent
		leftover--
	}
	return counts
}

// rngFromSeed returns a deterministic PRNG when seed is non-empty, and one
// seeded from the system CSPRNG when seed is empty (see NewHomophonicCipher
// for the rationale).
func rngFromSeed(seed string) (*mrand.Rand, error) {
	if seed == "" {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return nil, fmt.Errorf("не вдалося отримати системну випадковість: %w", err)
		}
		return mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(buf[:])))), nil //nolint:gosec // seed only, not the randomness itself
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(seed))
	return mrand.New(mrand.NewSource(int64(h.Sum64()))), nil //nolint:gosec // deterministic reproducibility seed, not a security boundary
}
