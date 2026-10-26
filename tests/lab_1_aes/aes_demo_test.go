// Package lab_1_aes_test exercises internal/lab_1_aes and contrasts it with
// the classic Vigenere cipher from internal/lab_1_algo (section 13:
// "порівняти навчальний шифр із AES GCM ... показати роль nonce і відмову
// розшифрування після зміни шифротексту").
package lab_1_aes_test

import (
	"bytes"
	"testing"

	aesdemo "4c-security-labs/internal/lab_1_aes"
	algo "4c-security-labs/internal/lab_1_algo"
)

func TestAESGCMRoundTrip(t *testing.T) {
	key, err := aesdemo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	plaintext := []byte("Слава Україні! Героям слава!")

	sealed, err := aesdemo.Seal(key, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := aesdemo.Open(key, sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open = %q, want %q", got, plaintext)
	}
}

// TestAESGCMNonceIsUniquePerCall demonstrates the role of the nonce: Seal
// generates a fresh one every call, so encrypting the exact same plaintext
// under the exact same key twice still produces two different byte strings
// — unlike the classic ciphers, where the same (key, plaintext) pair always
// maps to the same ciphertext, leaking that two messages are identical.
func TestAESGCMNonceIsUniquePerCall(t *testing.T) {
	key, err := aesdemo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	plaintext := []byte("однакове повідомлення")

	sealed1, err := aesdemo.Seal(key, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed2, err := aesdemo.Seal(key, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if bytes.Equal(sealed1, sealed2) {
		t.Fatal("two Seal calls with the same key and plaintext produced identical output; nonce reuse would break GCM's guarantees")
	}

	for _, sealed := range [][]byte{sealed1, sealed2} {
		got, err := aesdemo.Open(key, sealed)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("Open = %q, want %q", got, plaintext)
		}
	}
}

// TestAESGCMRejectsTamperedCiphertext demonstrates authenticated encryption:
// flipping a single bit anywhere in the sealed output — nonce, ciphertext or
// tag — makes Open fail instead of returning corrupted plaintext silently.
func TestAESGCMRejectsTamperedCiphertext(t *testing.T) {
	key, err := aesdemo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sealed, err := aesdemo.Seal(key, []byte("автентифіковане повідомлення"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for i := range sealed {
		tampered := append([]byte(nil), sealed...)
		tampered[i] ^= 0x01 // flip one bit

		if _, err := aesdemo.Open(key, tampered); err == nil {
			t.Fatalf("Open accepted ciphertext tampered at byte %d, want authentication failure", i)
		}
	}
}

func TestAESGCMWrongKeyFails(t *testing.T) {
	key1, err := aesdemo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key2, err := aesdemo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	sealed, err := aesdemo.Seal(key1, []byte("секрет"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := aesdemo.Open(key2, sealed); err == nil {
		t.Fatal("Open succeeded with the wrong key, want authentication failure")
	}
}

// TestComparisonVigenereHasNoTamperDetection is the direct counterpoint to
// TestAESGCMRejectsTamperedCiphertext: Vigenere (like every cipher in
// internal/lab_1_algo) provides confidentiality-by-obscurity only, with no
// integrity check at all. Flipping a letter in the ciphertext still
// "decrypts" successfully — to the wrong plaintext, with no error, no
// detectable signal that anything was tampered with. This is precisely the
// property AES-GCM's authentication tag closes off.
func TestComparisonVigenereHasNoTamperDetection(t *testing.T) {
	c := algo.NewVigenereCipher("")
	res, err := c.Encrypt("КЛЮЧ", "СЛАВА УКРАЇНІ")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tampered := []rune(res.Text)
	// Flip the first letter to a different one, deterministically.
	idx, _ := algo.DefaultAlphabet.IndexOf(tampered[0])
	tampered[0] = algo.DefaultAlphabet.RuneAt((idx + 1) % algo.DefaultAlphabet.Size())

	plain, err := c.Decrypt("КЛЮЧ", algo.Result{Text: string(tampered)})
	if err != nil {
		t.Fatalf("Vigenere Decrypt unexpectedly returned an error on tampered ciphertext: %v (AES-GCM would, Vigenere should not)", err)
	}
	if plain == "СЛАВА УКРАЇНІ" {
		t.Fatal("expected tampering to change the decrypted plaintext")
	}
	// The point being demonstrated: decryption "succeeded" with no error at
	// all, silently returning different (wrong) plaintext instead.
}
