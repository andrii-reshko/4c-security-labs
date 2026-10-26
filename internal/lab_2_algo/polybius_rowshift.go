package lab_2_algo

import "4c-security-labs/internal/shared"

// PolybiusRowShiftCipher implements the "row shift" mode documented
// separately from the coordinate mode in section 4.2/4.5: a symbol is
// replaced by the symbol from the next row of the same column (cyclic
// across the square's 6 rows). This is a simple monoalphabetic
// substitution over the square's symbols, not coordinate coding — section
// 4.2 asks that this distinction be stated explicitly. Symbols outside the
// square (spaces, punctuation, digits not in the square) are preserved
// unchanged.
type PolybiusRowShiftCipher struct{}

func NewPolybiusRowShiftCipher() *PolybiusRowShiftCipher {
	return &PolybiusRowShiftCipher{}
}

func (c *PolybiusRowShiftCipher) Algorithm() Algorithm {
	return AlgorithmPolybiusRowShift
}

func (c *PolybiusRowShiftCipher) ValidateKey(lang Language, key string) error {
	_, err := BuildSquare(lang, key)
	return err
}

func (c *PolybiusRowShiftCipher) Encrypt(lang Language, key, plaintext string) (Result, error) {
	sq, err := BuildSquare(lang, key)
	if err != nil {
		return Result{}, err
	}
	prepared := shared.Prepare(plaintext)
	out := make([]rune, 0, len(prepared))
	for _, r := range prepared {
		if shifted, ok := sq.RowShift(r); ok {
			out = append(out, shifted)
			continue
		}
		out = append(out, r)
	}
	return Result{Text: string(out)}, nil
}

func (c *PolybiusRowShiftCipher) Decrypt(lang Language, key string, in Result) (string, error) {
	sq, err := BuildSquare(lang, key)
	if err != nil {
		return "", err
	}
	prepared := shared.Prepare(in.Text)
	out := make([]rune, 0, len(prepared))
	for _, r := range prepared {
		if shifted, ok := sq.RowUnshift(r); ok {
			out = append(out, shifted)
			continue
		}
		out = append(out, r)
	}
	return string(out), nil
}
