package lab_1_algo

import "4c-security-labs/internal/shared"

// Algorithm identifies one of the four mandatory ciphers (section 6.1).
type Algorithm string

const (
	AlgorithmSubstitution Algorithm = "substitution"
	AlgorithmVigenere     Algorithm = "vigenere"
	AlgorithmBlockPerm    Algorithm = "block_permutation"
	AlgorithmColumnar     Algorithm = "columnar"
	// AlgorithmHomophonic is the "додаткове завдання" (section 13) homophonic
	// substitution cipher. It is not one of the four mandatory algorithms
	// (section 6.1) but is dispatched through the same CipherService/Cipher
	// machinery.
	AlgorithmHomophonic Algorithm = "homophonic"
)

// Algorithms lists every supported algorithm in a stable, UI-friendly order.
// The first four are the mandatory level (section 6.1); AlgorithmHomophonic
// is the additional one from section 13.
var Algorithms = []Algorithm{
	AlgorithmSubstitution,
	AlgorithmVigenere,
	AlgorithmBlockPerm,
	AlgorithmColumnar,
	AlgorithmHomophonic,
}

// Label returns a human-readable Ukrainian name for the algorithm.
func (a Algorithm) Label() string {
	switch a {
	case AlgorithmSubstitution:
		return "Проста одноалфавітна підстановка"
	case AlgorithmVigenere:
		return "Шифр Віженера"
	case AlgorithmBlockPerm:
		return "Блокова перестановка"
	case AlgorithmColumnar:
		return "Вертикальна перестановка"
	case AlgorithmHomophonic:
		return "Гомофонна підстановка (додатково)"
	default:
		return string(a)
	}
}

// Result is what every cipher returns from Encrypt. Meta carries algorithm
// specific side information that decryption needs back (e.g. the number of
// padding characters appended by the columnar cipher, section 6.2 table).
// The implementation is shared with internal/lab_2_algo via internal/shared.
type Result = shared.Result

// Cipher is the shared, interface-only contract between the cryptographic
// core and any delivery mechanism (TUI, CLI flags, tests). It intentionally
// knows nothing about terminals, files or flags.
type Cipher interface {
	Algorithm() Algorithm
	ValidateKey(key string) error
	Encrypt(key, plaintext string) (Result, error)
	Decrypt(key string, in Result) (string, error)
	// DefaultKey returns the permanent key this cipher was constructed with
	// (typically loaded from .env in composition_root.go), or "" if none was
	// configured. The delivery layer uses it to skip manual key entry.
	DefaultKey() string
}
