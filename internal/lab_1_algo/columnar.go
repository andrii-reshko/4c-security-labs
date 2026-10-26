package lab_1_algo

import "fmt"

// paddingFiller is appended to the last row of the grid when the text does
// not divide evenly by the key length (section 4.6). It is stripped back out
// on decryption using the exact count stored in Result.Meta, never by
// pattern-matching the filler rune itself (section 4.6 explicitly warns
// against removing "all such symbols").
const paddingFiller = '\uE000'

// MetaPadding is the Result.Meta key under which ColumnarCipher reports how
// many filler runes it appended.
const MetaPadding = "padding"

// ColumnarCipher implements the vertical (columnar) transposition from
// section 4.6: the text is written row by row into a grid with as many
// columns as the key is long, then read out column by column in the order
// given by the key.
type ColumnarCipher struct {
	// Mode controls whether non-alphabet characters are kept (default,
	// reversible) or stripped before the grid is built.
	Mode PrepMode

	defaultKey string
}

// NewColumnarCipher constructs the columnar transposition cipher in Preserve
// mode. defaultKey is the permanent column order wired in from
// composition_root.go (e.g. loaded from .env); pass "" if none should be
// configured.
func NewColumnarCipher(defaultKey string) *ColumnarCipher {
	return &ColumnarCipher{Mode: PrepPreserve, defaultKey: defaultKey}
}

func (c *ColumnarCipher) Algorithm() Algorithm {
	return AlgorithmColumnar
}

func (c *ColumnarCipher) DefaultKey() string {
	return c.defaultKey
}

func (c *ColumnarCipher) ValidateKey(key string) error {
	_, err := parsePermutation(key)
	return err
}

func (c *ColumnarCipher) Encrypt(key, plaintext string) (Result, error) {
	colOrder, err := parsePermutation(key)
	if err != nil {
		return Result{}, err
	}
	k := len(colOrder)
	prepared := PrepareWithMode(plaintext, c.Mode)
	runes := []rune(prepared)

	pad := 0
	if rem := len(runes) % k; rem != 0 {
		pad = k - rem
	}
	padded := make([]rune, len(runes)+pad)
	copy(padded, runes)
	for i := len(runes); i < len(padded); i++ {
		padded[i] = paddingFiller
	}
	rows := len(padded) / k

	out := make([]rune, 0, len(padded))
	for _, col := range colOrder {
		for row := 0; row < rows; row++ {
			out = append(out, padded[row*k+col])
		}
	}

	return Result{
		Text: string(out),
		Meta: map[string]string{MetaPadding: fmt.Sprintf("%d", pad)},
	}, nil
}

func (c *ColumnarCipher) Decrypt(key string, in Result) (string, error) {
	colOrder, err := parsePermutation(key)
	if err != nil {
		return "", err
	}
	k := len(colOrder)

	pad, err := parsePaddingMeta(in.Meta, k)
	if err != nil {
		return "", err
	}

	runes := []rune(in.Text)
	if len(runes)%k != 0 {
		return "", fmt.Errorf("%w: довжина шифротексту %d не кратна %d стовпцям", ErrNotAPermutation, len(runes), k)
	}
	rows := len(runes) / k

	grid := make([]rune, len(runes))
	idx := 0
	for _, col := range colOrder {
		for row := 0; row < rows; row++ {
			grid[row*k+col] = runes[idx]
			idx++
		}
	}

	plain := grid[:len(grid)-pad]
	return string(plain), nil
}

func parsePaddingMeta(meta map[string]string, k int) (int, error) {
	raw, ok := meta[MetaPadding]
	if !ok {
		return 0, nil
	}
	var pad int
	if _, err := fmt.Sscanf(raw, "%d", &pad); err != nil {
		return 0, fmt.Errorf("%w: некоректне значення доповнення %q", ErrPaddingOutOfRange, raw)
	}
	if pad < 0 || pad >= k {
		return 0, fmt.Errorf("%w: %d", ErrPaddingOutOfRange, pad)
	}
	return pad, nil
}
