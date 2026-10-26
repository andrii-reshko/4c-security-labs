package lab_2

import (
	"fmt"

	algo "4c-security-labs/internal/lab_2_algo"
	"4c-security-labs/internal/shared"
)

// CipherService is the single façade the delivery layer (CLI, tests) talks
// to. It knows how to find the right Cipher for an Algorithm and always
// validates the key before attempting a transformation (section 6.2,
// "перевірка ключів і режимів до початку обробки"). The concrete cipher
// implementations it dispatches to live in internal/lab_2_algo.
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

// ValidateKey checks a key against the given algorithm's rules, for the
// given language, without running any transformation.
func (s *CipherService) ValidateKey(a algo.Algorithm, lang algo.Language, key string) error {
	c, err := s.Get(a)
	if err != nil {
		return err
	}
	return c.ValidateKey(lang, key)
}

// Encrypt validates the key and, if it is accepted, encrypts plaintext.
func (s *CipherService) Encrypt(a algo.Algorithm, lang algo.Language, key, plaintext string) (algo.Result, error) {
	c, err := s.Get(a)
	if err != nil {
		return algo.Result{}, err
	}
	if err := c.ValidateKey(lang, key); err != nil {
		return algo.Result{}, err
	}
	return c.Encrypt(lang, key, plaintext)
}

// Decrypt validates the key and, if it is accepted, decrypts in.
func (s *CipherService) Decrypt(a algo.Algorithm, lang algo.Language, key string, in algo.Result) (string, error) {
	c, err := s.Get(a)
	if err != nil {
		return "", err
	}
	if err := c.ValidateKey(lang, key); err != nil {
		return "", err
	}
	return c.Decrypt(lang, key, in)
}
