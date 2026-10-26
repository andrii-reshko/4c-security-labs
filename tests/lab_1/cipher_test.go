// Package lab_1_test holds the test suite for the cipher implementations in
// internal/lab_1_algo (plus the internal/lab_1 CipherService that
// dispatches to them). It lives outside both packages, importing them like
// any other consumer, so that implementation code and the testing harness
// stay in clearly separate directories.
package lab_1_test

import (
	"strings"
	"testing"

	lab_1 "4c-security-labs/internal/lab_1"
	algo "4c-security-labs/internal/lab_1_algo"
)

// --- Control vectors (section 7) -------------------------------------------
//
// The lab's PDF renders two of its four control vectors with what look like
// OCR artifacts: the substitution example is missing one letter (ІНЯЬЯ
// became ІНЬЯ) and the Vigenere example confuses Ї with the visually
// similar І at one position. Both anomalies were traced by hand-deriving
// the vectors from the formal definitions in sections 4.2/4.4, which match
// the PDF's own wording exactly everywhere else (every other character of
// both vectors lines up, as do the block and columnar vectors, which have
// no such artifact). The values asserted below are the mathematically
// correct outputs of the documented algorithms.

func TestControlVectorReverseAlphabetSubstitution(t *testing.T) {
	reversed := reverseString(algo.DefaultAlphabet.String())
	c := algo.NewSubstitutionCipher("")

	res, err := c.Encrypt(reversed, "СЛАВА УКРАЇНІ")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "ІНЯЬЯ ЗОЇЯРЛС"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt(reversed, res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "СЛАВА УКРАЇНІ" {
		t.Fatalf("Decrypt = %q, want %q", plain, "СЛАВА УКРАЇНІ")
	}
}

func TestControlVectorVigenere(t *testing.T) {
	c := algo.NewVigenereCipher("")

	res, err := c.Encrypt("КЛЮЧ", "СЛАВА УКРАЇНІ")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "ВЬЮЩК ДЇККЧЛД"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt("КЛЮЧ", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "СЛАВА УКРАЇНІ" {
		t.Fatalf("Decrypt = %q, want %q", plain, "СЛАВА УКРАЇНІ")
	}
}

func TestControlVectorBlockPermutation(t *testing.T) {
	c := algo.NewBlockPermutationCipher("")
	c.Mode = algo.PrepLettersOnly

	res, err := c.Encrypt("3 2 5 1 4", "СЛАВА УКРАЇНІ")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "АЛАСВРКЇУАНІ"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	// Section 7 notes that, in letters-only mode, the reversibility baseline
	// is the already-prepared (space-stripped) text.
	plain, err := c.Decrypt("3 2 5 1 4", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "СЛАВАУКРАЇНІ" {
		t.Fatalf("Decrypt = %q, want %q", plain, "СЛАВАУКРАЇНІ")
	}
}

func TestControlVectorColumnar(t *testing.T) {
	c := algo.NewColumnarCipher("")

	res, err := c.Encrypt("3 1 4 2", "КРИПТОГРАФІЯ")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "ИГІКТАПРЯРОФ"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}
	if res.Meta[algo.MetaPadding] != "0" {
		t.Fatalf("padding = %q, want 0 (12 letters / 4 columns divides evenly)", res.Meta[algo.MetaPadding])
	}

	plain, err := c.Decrypt("3 1 4 2", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "КРИПТОГРАФІЯ" {
		t.Fatalf("Decrypt = %q, want %q", plain, "КРИПТОГРАФІЯ")
	}
}

// --- Reversibility: D_k(E_k(x)) == x for >=10 messages per algorithm -------

func TestReversibilityAllAlgorithms(t *testing.T) {
	messages := []string{
		"ПРИВІТ СВІТЕ",
		"ҐАВА ЇЖАК ЄВРО ІКС",
		"ОДИН ДВА ТРИ ЧОТИРИ ПЯТЬ",
		"КРИПТОГРАФІЯ ТА БЕЗПЕКА ДАНИХ",
		"ЛАБОРАТОРНА РОБОТА З ЗАХИСТУ ІНФОРМАЦІЇ",
		"ШИФР ПІДСТАНОВКИ ТА ПЕРЕСТАНОВКИ",
		"УКРАЇНСЬКИЙ АЛФАВІТ МАЄ ТРИДЦЯТЬ ТРИ ЛІТЕРИ",
		"ТЕСТУВАННЯ ПРОГРАМНОГО ЗАБЕЗПЕЧЕННЯ",
		"НОРМАЛІЗАЦІЯ ЮНІКОД NFC",
		"ВІЖЕНЕР ГАММУЄ ТЕКСТ ЗА КЛЮЧЕМ",
	}

	t.Run("substitution", func(t *testing.T) {
		c := algo.NewSubstitutionCipher("")
		for _, msg := range messages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt("КРИПТОГРАФІЯ", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt("КРИПТОГРАФІЯ", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})

	t.Run("vigenere", func(t *testing.T) {
		c := algo.NewVigenereCipher("")
		for _, msg := range messages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt("ТАЄМНИЦЯ", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt("ТАЄМНИЦЯ", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})

	t.Run("block_permutation_preserve", func(t *testing.T) {
		c := algo.NewBlockPermutationCipher("")
		for _, msg := range messages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt("4 1 3 2 6 5", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt("4 1 3 2 6 5", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})

	t.Run("columnar", func(t *testing.T) {
		c := algo.NewColumnarCipher("")
		for _, msg := range messages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt("5 3 1 4 2", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt("5 3 1 4 2", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})
}

// --- Ukrainian letters -------------------------------------------------

func TestUkrainianSpecialLetters(t *testing.T) {
	msg := "ҐАВА ЄВРОПА ІКС ЇЖАК"
	for _, r := range []rune{'Ґ', 'Є', 'І', 'Ї'} {
		if !strings.ContainsRune(msg, r) {
			t.Fatalf("test message must contain %q", r)
		}
		if !algo.DefaultAlphabet.Contains(r) {
			t.Fatalf("%q must belong to the base alphabet", r)
		}
	}

	c := algo.NewVigenereCipher("")
	res, err := c.Encrypt("КЛЮЧ", msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	for _, r := range res.Text {
		if r != ' ' && !algo.DefaultAlphabet.Contains(r) {
			t.Fatalf("ciphertext contains damaged/unsupported rune %q", r)
		}
	}
	plain, err := c.Decrypt("КЛЮЧ", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != algo.Prepare(msg) {
		t.Fatalf("round-trip = %q, want %q", plain, algo.Prepare(msg))
	}
}

// --- Boundaries ----------------------------------------------------------

func TestBoundariesBlockPermutation(t *testing.T) {
	c := algo.NewBlockPermutationCipher("")
	c.Mode = algo.PrepLettersOnly
	key := "3 2 5 1 4" // n = 5

	cases := []string{
		"",       // empty text
		"А",      // single symbol
		"АБВГҐ",  // length == block
		"АБВГ",   // length == block - 1
		"АБВГҐД", // length == block + 1
	}
	for _, text := range cases {
		res, err := c.Encrypt(key, text)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", text, err)
		}
		plain, err := c.Decrypt(key, res)
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", text, err)
		}
		if plain != algo.Prepare(text) {
			t.Fatalf("round-trip(%q) = %q, want %q", text, plain, algo.Prepare(text))
		}
	}
}

func TestBoundariesColumnar(t *testing.T) {
	c := algo.NewColumnarCipher("")
	key := "3 1 4 2" // k = 4

	cases := []string{
		"",
		"А",
		"АБВГ",  // length == k
		"АБВ",   // length == k - 1 (needs padding)
		"АБВГД", // length == k + 1 (needs padding)
	}
	for _, text := range cases {
		res, err := c.Encrypt(key, text)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", text, err)
		}
		plain, err := c.Decrypt(key, res)
		if err != nil {
			t.Fatalf("Decrypt(%q): %v", text, err)
		}
		if plain != algo.Prepare(text) {
			t.Fatalf("round-trip(%q) = %q, want %q", text, plain, algo.Prepare(text))
		}
	}
}

// --- Formatting: spaces, newlines, digits, punctuation --------------------

func TestFormattingIsPreserved(t *testing.T) {
	msg := "Рядок1,\nРядок2; тест-42!"
	c := algo.NewVigenereCipher("")
	res, err := c.Encrypt("КЛЮЧ", msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := c.Decrypt("КЛЮЧ", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != algo.Prepare(msg) {
		t.Fatalf("round-trip = %q, want %q", plain, algo.Prepare(msg))
	}
}

// --- Constructor-injected default keys --------------------------------------

func TestDefaultKeyInjectedViaConstructor(t *testing.T) {
	cases := []struct {
		name   string
		cipher algo.Cipher
		want   string
	}{
		{"substitution", algo.NewSubstitutionCipher("КРИПТОГРАФІЯ"), "КРИПТОГРАФІЯ"},
		{"vigenere", algo.NewVigenereCipher("КЛЮЧ"), "КЛЮЧ"},
		{"block_permutation", algo.NewBlockPermutationCipher("3 2 5 1 4"), "3 2 5 1 4"},
		{"columnar", algo.NewColumnarCipher("3 1 4 2"), "3 1 4 2"},
		{"substitution_empty", algo.NewSubstitutionCipher(""), ""},
	}
	for _, tc := range cases {
		if got := tc.cipher.DefaultKey(); got != tc.want {
			t.Errorf("%s: DefaultKey() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestServiceExposesDefaultKeyPerAlgorithm(t *testing.T) {
	service := lab_1.NewCipherService(
		algo.NewSubstitutionCipher("КРИПТОГРАФІЯ"),
		algo.NewVigenereCipher("КЛЮЧ"),
		algo.NewBlockPermutationCipher(""),
		algo.NewColumnarCipher("3 1 4 2"),
	)

	if got := service.DefaultKey(algo.AlgorithmSubstitution); got != "КРИПТОГРАФІЯ" {
		t.Errorf("DefaultKey(substitution) = %q, want %q", got, "КРИПТОГРАФІЯ")
	}
	if got := service.DefaultKey(algo.AlgorithmVigenere); got != "КЛЮЧ" {
		t.Errorf("DefaultKey(vigenere) = %q, want %q", got, "КЛЮЧ")
	}
	if got := service.DefaultKey(algo.AlgorithmBlockPerm); got != "" {
		t.Errorf("DefaultKey(block_permutation) = %q, want empty", got)
	}
	if got := service.DefaultKey(algo.AlgorithmColumnar); got != "3 1 4 2" {
		t.Errorf("DefaultKey(columnar) = %q, want %q", got, "3 1 4 2")
	}
	if got := service.DefaultKey(algo.Algorithm("unknown")); got != "" {
		t.Errorf("DefaultKey(unknown) = %q, want empty", got)
	}
}

// --- Negative cases --------------------------------------------------------

func TestNegativeEmptyKeys(t *testing.T) {
	ciphers := []algo.Cipher{
		algo.NewSubstitutionCipher(""),
		algo.NewVigenereCipher(""),
		algo.NewBlockPermutationCipher(""),
		algo.NewColumnarCipher(""),
	}
	for _, c := range ciphers {
		if err := c.ValidateKey(""); err == nil {
			t.Fatalf("%s: ValidateKey(\"\") should fail", c.Algorithm())
		}
	}
}

func TestNegativePermutationRepeats(t *testing.T) {
	c := algo.NewBlockPermutationCipher("")
	if err := c.ValidateKey("1 2 2 4"); err == nil {
		t.Fatal("expected error for repeated index in permutation")
	}
}

func TestNegativePermutationOutOfRange(t *testing.T) {
	c := algo.NewColumnarCipher("")
	if err := c.ValidateKey("1 2 3 9"); err == nil {
		t.Fatal("expected error for out-of-range index in permutation")
	}
}

func TestNegativeVigenereLetterOutsideAlphabet(t *testing.T) {
	c := algo.NewVigenereCipher("")
	if err := c.ValidateKey("KEY"); err == nil { // Latin letters, not in alphabet A
		t.Fatal("expected error for key with letters outside the base alphabet")
	}
}

func TestNegativeColumnarPaddingOutOfRange(t *testing.T) {
	c := algo.NewColumnarCipher("")
	_, err := c.Decrypt("3 1 4 2", algo.Result{
		Text: "АБВГ",
		Meta: map[string]string{algo.MetaPadding: "9"},
	})
	if err == nil {
		t.Fatal("expected error for padding count out of range")
	}
}

// Note: UTF-8 file I/O (ReadUTF8File/WriteUTF8File) lives in the separate
// internal/lab_1_ext package, not here — see tests/lab_1_ext/file_test.go.

// --- helpers ----------------------------------------------------------------

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
