package lab_1_algo

type BlockPermutationCipher struct {
	// Mode controls whether non-alphabet characters are kept
	Mode PrepMode

	defaultKey string
}

func NewBlockPermutationCipher(defaultKey string) *BlockPermutationCipher {
	return &BlockPermutationCipher{Mode: PrepPreserve, defaultKey: defaultKey}
}

func (c *BlockPermutationCipher) Algorithm() Algorithm {
	return AlgorithmBlockPerm
}

func (c *BlockPermutationCipher) DefaultKey() string {
	return c.defaultKey
}

func (c *BlockPermutationCipher) ValidateKey(key string) error {
	_, err := parsePermutation(key)
	return err
}

func (c *BlockPermutationCipher) Encrypt(key, plaintext string) (Result, error) {
	perm, err := parsePermutation(key)
	if err != nil {
		return Result{}, err
	}
	prepared := PrepareWithMode(plaintext, c.Mode)
	out := applyBlocks([]rune(prepared), perm)
	return Result{Text: string(out)}, nil
}

func (c *BlockPermutationCipher) Decrypt(key string, in Result) (string, error) {
	perm, err := parsePermutation(key)
	if err != nil {
		return "", err
	}
	inv := inversePermutation(perm)
	out := applyBlocks([]rune(in.Text), inv)
	return string(out), nil
}

// applyBlocks rearranges every full block of len(perm) runes according to
// perm (zero-based: out[j] = block[perm[j]]). Trailing runes that do not
// fill a whole block pass through unchanged.
func applyBlocks(runes []rune, perm []int) []rune {
	n := len(perm)
	out := make([]rune, len(runes))
	copy(out, runes)

	for start := 0; start+n <= len(runes); start += n {
		block := runes[start : start+n]
		for j := 0; j < n; j++ {
			out[start+j] = block[perm[j]]
		}
	}
	return out
}
