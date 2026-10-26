package lab_2_algo

import "fmt"

// GronsfeldCipher implements the polyalphabetic substitution with a digit
// key from section 4.7. The key is kept as a string of digits, not an
// integer, to preserve leading zeros. Digits are applied cyclically only to
// letters of the chosen alphabet; spaces, digits in the text and
// punctuation are left unchanged and do not advance the key.
type GronsfeldCipher struct{}

func NewGronsfeldCipher() *GronsfeldCipher {
	return &GronsfeldCipher{}
}

func (c *GronsfeldCipher) Algorithm() Algorithm {
	return AlgorithmGronsfeld
}

func (c *GronsfeldCipher) ValidateKey(lang Language, key string) error {
	if _, err := digitsKey(key); err != nil {
		return err
	}
	_, err := Letters(lang)
	return err
}

// digitsKey parses and validates a Gronsfeld key per section 4.7: not
// empty, digits only, and not composed entirely of zeros.
func digitsKey(key string) ([]int, error) {
	if key == "" {
		return nil, ErrEmptyKey
	}
	digits := make([]int, 0, len(key))
	hasNonZero := false
	for _, r := range key {
		if r < '0' || r > '9' {
			return nil, fmt.Errorf("%w: %q", ErrInvalidDigitKey, r)
		}
		d := int(r - '0')
		if d != 0 {
			hasNonZero = true
		}
		digits = append(digits, d)
	}
	if !hasNonZero {
		return nil, ErrDigitKeyAllZeros
	}
	return digits, nil
}

func (c *GronsfeldCipher) Encrypt(lang Language, key, plaintext string) (Result, error) {
	digits, err := digitsKey(key)
	if err != nil {
		return Result{}, err
	}
	alphabet, err := Letters(lang)
	if err != nil {
		return Result{}, err
	}
	m := alphabet.Size()
	prepared := Prepare(plaintext)
	out := make([]rune, 0, len(prepared))
	j := 0
	for _, r := range prepared {
		p, ok := alphabet.IndexOf(r)
		if !ok {
			out = append(out, r)
			continue
		}
		d := digits[j%len(digits)]
		j++
		ci := (p + d) % m
		out = append(out, alphabet.RuneAt(ci))
	}
	return Result{Text: string(out)}, nil
}

func (c *GronsfeldCipher) Decrypt(lang Language, key string, in Result) (string, error) {
	digits, err := digitsKey(key)
	if err != nil {
		return "", err
	}
	alphabet, err := Letters(lang)
	if err != nil {
		return "", err
	}
	m := alphabet.Size()
	prepared := Prepare(in.Text)
	out := make([]rune, 0, len(prepared))
	j := 0
	for _, r := range prepared {
		ci, ok := alphabet.IndexOf(r)
		if !ok {
			out = append(out, r)
			continue
		}
		d := digits[j%len(digits)]
		j++
		pi := ((ci-d)%m + m) % m
		out = append(out, alphabet.RuneAt(pi))
	}
	return string(out), nil
}
