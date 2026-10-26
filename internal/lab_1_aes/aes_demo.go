// Package lab_1_aes is the "порівняти навчальний шифр із AES GCM" part of
// section 13. It exists purely to contrast the classic ciphers in
// internal/lab_1_algo with a modern, authenticated cipher: it wraps
// crypto/aes and crypto/cipher from the Go standard library — AES-GCM
// itself is never reimplemented here, per the assignment's explicit
// instruction.
package lab_1_aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// KeySize is 32 bytes (AES-256).
const KeySize = 32

// GenerateKey returns a fresh random AES-256 key from the system CSPRNG.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("не вдалося згенерувати ключ AES: %w", err)
	}
	return key, nil
}

// Seal encrypts and authenticates plaintext under key using AES-GCM.
//
// A fresh random nonce is generated on every call and prepended to the
// returned bytes (nonce || ciphertext || authentication tag) — reusing a
// nonce with the same key is the one mistake that breaks GCM's guarantees,
// so Seal never lets the caller supply or reuse one. Unlike the classic
// ciphers, the output also carries an authentication tag: Open rejects any
// tampering instead of silently returning wrong plaintext.
func Seal(key, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("не вдалося згенерувати nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open verifies and decrypts sealed (as produced by Seal) under key. Any
// modification to sealed — including a single flipped bit in the
// ciphertext, the tag, or the nonce — makes this return an error instead of
// plaintext.
func Open(key, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("шифротекст закороткий: немає місця для nonce AES-GCM")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("автентифікація AES-GCM не пройшла (шифротекст або ключ некоректні): %w", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("не вдалося ініціалізувати AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("не вдалося ініціалізувати GCM: %w", err)
	}
	return gcm, nil
}
