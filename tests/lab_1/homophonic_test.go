package lab_1_test

import (
	"testing"

	algo "4c-security-labs/internal/lab_1_algo"
)

// TestHomophonicReproducibleWithSeed verifies section 4.3's two modes: a
// non-empty seed ("явно заданий тестовий параметр") makes the homophone
// choice reproducible, and different seeds (very likely) choose differently.
func TestHomophonicReproducibleWithSeed(t *testing.T) {
	c := algo.NewHomophonicCipher("")
	msg := "ПРИВІТ СВІТЕ ЦЕ ТЕСТ ГОМОФОННОЇ ПІДСТАНОВКИ"

	res1, err := c.Encrypt("test-seed-1", msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	res2, err := c.Encrypt("test-seed-1", msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if res1.Text != res2.Text {
		t.Fatalf("same seed produced different ciphertexts:\n%q\n%q", res1.Text, res2.Text)
	}

	res3, err := c.Encrypt("test-seed-2", msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if res1.Text == res3.Text {
		t.Fatalf("different seeds produced identical ciphertexts, expected homophone choices to differ")
	}
}

// TestHomophonicRoundTrip checks decryption recovers the letters-only,
// upper-cased, NFC-normalized plaintext regardless of which homophone codes
// were chosen during encryption.
func TestHomophonicRoundTrip(t *testing.T) {
	c := algo.NewHomophonicCipher("")
	messages := []string{
		"ПРИВІТ СВІТЕ",
		"ҐАВА ЇЖАК ЄВРО ІКС",
		"КРИПТОГРАФІЯ ТА БЕЗПЕКА ДАНИХ",
	}
	for _, msg := range messages {
		want := algo.PrepareWithMode(msg, algo.PrepLettersOnly)
		res, err := c.Encrypt("round-trip-seed", msg)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", msg, err)
		}
		plain, err := c.Decrypt("round-trip-seed", res)
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", msg, err)
		}
		if plain != want {
			t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, want)
		}
	}
}

// TestHomophonicFrequentLettersGetMoreCodes spot-checks that the homophone
// table actually gives common Ukrainian letters more alternative codes than
// rare ones — otherwise the cipher would not resist frequency analysis any
// better than plain substitution, defeating the point of section 4.3.
func TestHomophonicFrequentLettersGetMoreCodes(t *testing.T) {
	common := algo.HomophoneCodeCount('О')
	rare := algo.HomophoneCodeCount('Ґ')
	if common <= rare {
		t.Fatalf("expected common letter О to have more homophone codes than rare letter Ґ, got О=%d Ґ=%d", common, rare)
	}
}
