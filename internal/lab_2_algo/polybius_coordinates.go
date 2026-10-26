package lab_2_algo

import (
	"fmt"
	"strconv"
	"strings"

	"4c-security-labs/internal/shared"
)

// PolybiusCoordinatesCipher implements the coordinate mode from section 4.4:
// every symbol is replaced by its 1-based "row column" pair, tokens
// separated by a single space. The base level only accepts symbols that
// belong to the chosen square (section 4.1: "базовий рівень приймає лише
// символи вибраного квадрата; видалення пробілів має бути окремою, видимою
// операцією підготовки тексту") — callers must strip spaces/punctuation
// from the plaintext themselves before calling Encrypt.
type PolybiusCoordinatesCipher struct{}

func NewPolybiusCoordinatesCipher() *PolybiusCoordinatesCipher {
	return &PolybiusCoordinatesCipher{}
}

func (c *PolybiusCoordinatesCipher) Algorithm() Algorithm {
	return AlgorithmPolybiusCoordinates
}

func (c *PolybiusCoordinatesCipher) ValidateKey(lang Language, key string) error {
	_, err := BuildSquare(lang, key)
	return err
}

func (c *PolybiusCoordinatesCipher) Encrypt(lang Language, key, plaintext string) (Result, error) {
	sq, err := BuildSquare(lang, key)
	if err != nil {
		return Result{}, err
	}
	prepared := shared.Prepare(plaintext)
	tokens := make([]string, 0, len(prepared))
	for _, r := range prepared {
		coord, ok := sq.Coordinates(r)
		if !ok {
			return Result{}, fmt.Errorf("%w: %q не належить обраному квадрату", ErrUnsupportedRune, r)
		}
		tokens = append(tokens, strconv.Itoa(coord[0])+strconv.Itoa(coord[1]))
	}
	return Result{Text: strings.Join(tokens, " ")}, nil
}

func (c *PolybiusCoordinatesCipher) Decrypt(lang Language, key string, in Result) (string, error) {
	sq, err := BuildSquare(lang, key)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(in.Text)
	if trimmed == "" {
		return "", nil
	}
	tokens := strings.Fields(trimmed)
	out := make([]rune, 0, len(tokens))
	for _, tok := range tokens {
		row, col, err := parseToken(tok)
		if err != nil {
			return "", err
		}
		r, ok := sq.At(row, col)
		if !ok {
			return "", fmt.Errorf("%w: %q", ErrInvalidToken, tok)
		}
		out = append(out, r)
	}
	return string(out), nil
}

// parseToken validates a coordinate token per section 4.4: exactly two
// digits, each in [1, SquareDim]. "00", "17", "61", "67", a single digit or
// non-digit text are all rejected (section 4.4, 6.2).
func parseToken(tok string) (int, int, error) {
	if len(tok) != 2 {
		return 0, 0, fmt.Errorf("%w: %q", ErrInvalidToken, tok)
	}
	rowDigit, colDigit := tok[0], tok[1]
	if rowDigit < '0' || rowDigit > '9' || colDigit < '0' || colDigit > '9' {
		return 0, 0, fmt.Errorf("%w: %q", ErrInvalidToken, tok)
	}
	row := int(rowDigit - '0')
	col := int(colDigit - '0')
	if row < 1 || row > SquareDim || col < 1 || col > SquareDim {
		return 0, 0, fmt.Errorf("%w: %q", ErrInvalidToken, tok)
	}
	return row, col, nil
}
