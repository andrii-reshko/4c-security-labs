package lab_1_algo

import "fmt"

// SubstitutionCipher implements the simple monoalphabetic substitution from
// section 4.2. The key is a keyword W; the substitution table B is derived
// from it deterministically (BuildTable).
type SubstitutionCipher struct {
	defaultKey string
}

// NewSubstitutionCipher constructs the simple substitution cipher. defaultKey
// is the permanent keyword wired in from composition_root.go (e.g. loaded
// from .env); pass "" if none should be configured.
func NewSubstitutionCipher(defaultKey string) *SubstitutionCipher {
	return &SubstitutionCipher{defaultKey: defaultKey}
}

func (c *SubstitutionCipher) Algorithm() Algorithm {
	return AlgorithmSubstitution
}

func (c *SubstitutionCipher) DefaultKey() string {
	return c.defaultKey
}

// BuildTable turns a keyword into the 33-letter table B described in
// section 4.2: normalize, drop repeated letters keeping first occurrence,
// then append every unused letter of A in alphabet order.
func BuildTable(keyword string) ([]rune, error) {
	prepared := PrepareWithMode(keyword, PrepLettersOnly)
	if prepared == "" {
		return nil, ErrEmptyKey
	}

	seen := make(map[rune]bool, DefaultAlphabet.Size())
	table := make([]rune, 0, DefaultAlphabet.Size())
	for _, r := range prepared {
		if seen[r] {
			continue
		}
		seen[r] = true
		table = append(table, r)
	}
	for _, r := range DefaultAlphabet.Runes() {
		if !seen[r] {
			seen[r] = true
			table = append(table, r)
		}
	}
	return table, nil
}

// ValidateKey checks the acceptance rule from section 6.2: after building,
// the table must have exactly m entries, contain only letters of A and no
// duplicates. BuildTable's construction already guarantees this once the
// keyword itself only contains alphabet letters, so this call doubles as the
// keyword sanity check.
func (c *SubstitutionCipher) ValidateKey(key string) error {
	table, err := BuildTable(key)
	if err != nil {
		return err
	}
	if len(table) != DefaultAlphabet.Size() {
		return fmt.Errorf("%w: отримано %d символів", ErrTableWrongLength, len(table))
	}
	seen := make(map[rune]bool, len(table))
	for _, r := range table {
		if !DefaultAlphabet.Contains(r) {
			return fmt.Errorf("%w: %q", ErrUnsupportedRune, r)
		}
		if seen[r] {
			return fmt.Errorf("%w: %q", ErrDuplicateLetter, r)
		}
		seen[r] = true
	}
	return nil
}

func (c *SubstitutionCipher) Encrypt(key, plaintext string) (Result, error) {
	table, err := c.keyTable(key)
	if err != nil {
		return Result{}, err
	}
	out := transformWithTable(plaintext, table)
	return Result{Text: out}, nil
}

func (c *SubstitutionCipher) Decrypt(key string, in Result) (string, error) {
	table, err := c.keyTable(key)
	if err != nil {
		return "", err
	}
	inverse := make([]rune, DefaultAlphabet.Size())
	for i, r := range table {
		idx, _ := DefaultAlphabet.IndexOf(r)
		inverse[idx] = DefaultAlphabet.RuneAt(i)
	}
	return transformWithTable(in.Text, inverse), nil
}

func (c *SubstitutionCipher) keyTable(key string) ([]rune, error) {
	if err := c.ValidateKey(key); err != nil {
		return nil, err
	}
	return BuildTable(key)
}

// transformWithTable maps every alphabet letter of the prepared text through
// table (indexed the same way as A) and leaves every other rune untouched,
// as required by the "Сторонні символи" row of section 5.
func transformWithTable(text string, table []rune) string {
	prepared := Prepare(text)
	out := make([]rune, 0, len(prepared))
	for _, r := range prepared {
		if idx, ok := DefaultAlphabet.IndexOf(r); ok {
			out = append(out, table[idx])
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
