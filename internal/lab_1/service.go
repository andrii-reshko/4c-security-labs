package lab_1

import (
	"fmt"

	algo "4c-security-labs/internal/lab_1_algo"
	"4c-security-labs/internal/shared"
)

// CipherService is the single façade the delivery layer (CLI, tests) talks
// to. It knows how to find the right Cipher for an Algorithm and always
// validates the key before attempting a transformation. The concrete cipher
// implementations it dispatches to live in internal/lab_1_algo.
type CipherService struct {
	ciphers map[algo.Algorithm]algo.Cipher
}

// NewCipherService registers every supplied Cipher under its own Algorithm.
func NewCipherService(ciphers ...algo.Cipher) *CipherService {
	m := make(map[algo.Algorithm]algo.Cipher, len(ciphers))
	for _, c := range ciphers {
		m[c.Algorithm()] = c
	}
	return &CipherService{ciphers: m}
}

// Get returns the cipher registered for the given algorithm.
func (s *CipherService) Get(a algo.Algorithm) (algo.Cipher, error) {
	c, ok := s.ciphers[a]
	if !ok {
		return nil, fmt.Errorf("%w: %s", shared.ErrUnknownAlgorithm, a)
	}
	return c, nil
}

// DefaultKey returns the permanent key the algorithm's cipher was
// constructed with in composition_root.go, or "" if none is configured.
func (s *CipherService) DefaultKey(a algo.Algorithm) string {
	c, err := s.Get(a)
	if err != nil {
		return ""
	}
	return c.DefaultKey()
}

// ValidateKey checks a key against the given algorithm's rules without
// running any transformation (section 6: "перевірка ключів до початку
// обробки").
func (s *CipherService) ValidateKey(a algo.Algorithm, key string) error {
	c, err := s.Get(a)
	if err != nil {
		return err
	}
	return c.ValidateKey(key)
}

// Encrypt validates the key and, if it is accepted, encrypts plaintext.
func (s *CipherService) Encrypt(a algo.Algorithm, key, plaintext string) (algo.Result, error) {
	c, err := s.Get(a)
	if err != nil {
		return algo.Result{}, err
	}
	if err := c.ValidateKey(key); err != nil {
		return algo.Result{}, err
	}
	return c.Encrypt(key, plaintext)
}

// Decrypt validates the key and, if it is accepted, decrypts in.
func (s *CipherService) Decrypt(a algo.Algorithm, key string, in algo.Result) (string, error) {
	c, err := s.Get(a)
	if err != nil {
		return "", err
	}
	if err := c.ValidateKey(key); err != nil {
		return "", err
	}
	return c.Decrypt(key, in)
}
