package lab_1_algo

import "fmt"

// VigenereCipher implements the periodic polyalphabetic substitution from
// section 4.4. Non-alphabet characters are preserved and do not advance the
// key position (section 5, "Сторонні символи").
type VigenereCipher struct {
	defaultKey string
}

// NewVigenereCipher constructs the Vigenere cipher. defaultKey is the
// permanent keyword wired in from composition_root.go (e.g. loaded from
// .env); pass "" if none should be configured.
func NewVigenereCipher(defaultKey string) *VigenereCipher {
	return &VigenereCipher{defaultKey: defaultKey}
}

func (c *VigenereCipher) Algorithm() Algorithm {
	return AlgorithmVigenere
}

func (c *VigenereCipher) DefaultKey() string {
	return c.defaultKey
}

// ValidateKey enforces the section 6.2 rule: the key must be non-empty and,
// after normalization, contain only letters of A.
func (c *VigenereCipher) ValidateKey(key string) error {
	_, err := c.keyIndices(key)
	return err
}

func (c *VigenereCipher) keyIndices(key string) ([]int, error) {
	prepared := Prepare(key)
	if prepared == "" {
		return nil, ErrEmptyKey
	}
	indices := make([]int, 0, len(prepared))
	for _, r := range prepared {
		idx, ok := DefaultAlphabet.IndexOf(r)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedRune, r)
		}
		indices = append(indices, idx)
	}
	return indices, nil
}

func (c *VigenereCipher) Encrypt(key, plaintext string) (Result, error) {
	keyIdx, err := c.keyIndices(key)
	if err != nil {
		return Result{}, err
	}
	m := DefaultAlphabet.Size()
	prepared := Prepare(plaintext)
	out := make([]rune, 0, len(prepared))
	pos := 0
	for _, r := range prepared {
		p, ok := DefaultAlphabet.IndexOf(r)
		if !ok {
			out = append(out, r)
			continue
		}
		k := keyIdx[pos%len(keyIdx)]
		pos++
		ci := (p + k) % m
		out = append(out, DefaultAlphabet.RuneAt(ci))
	}
	return Result{Text: string(out)}, nil
}

func (c *VigenereCipher) Decrypt(key string, in Result) (string, error) {
	keyIdx, err := c.keyIndices(key)
	if err != nil {
		return "", err
	}
	m := DefaultAlphabet.Size()
	prepared := Prepare(in.Text)
	out := make([]rune, 0, len(prepared))
	pos := 0
	for _, r := range prepared {
		ci, ok := DefaultAlphabet.IndexOf(r)
		if !ok {
			out = append(out, r)
			continue
		}
		k := keyIdx[pos%len(keyIdx)]
		pos++
		pi := ((ci-k)%m + m) % m
		out = append(out, DefaultAlphabet.RuneAt(pi))
	}
	return string(out), nil
}
