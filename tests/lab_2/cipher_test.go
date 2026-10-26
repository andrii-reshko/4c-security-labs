// Package lab_2_test holds the test suite for the cipher implementations in
// internal/lab_2_algo (plus the internal/lab_2 CipherService that dispatches
// to them). It lives outside both packages, importing them like any other
// consumer.
package lab_2_test

import (
	"testing"

	algo "4c-security-labs/internal/lab_2_algo"
)

// --- Control vectors (section 7) -------------------------------------------

func TestControlVectorPolybiusCoordinatesUkrainian(t *testing.T) {
	c := algo.NewPolybiusCoordinatesCipher()

	res, err := c.Encrypt(algo.LanguageUkrainian, "БЕЗПЕКА", "СЛАВА")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "44 35 16 21 16"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt(algo.LanguageUkrainian, "БЕЗПЕКА", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "СЛАВА" {
		t.Fatalf("Decrypt = %q, want %q", plain, "СЛАВА")
	}
}

func TestControlVectorPolybiusCoordinatesLatin(t *testing.T) {
	c := algo.NewPolybiusCoordinatesCipher()

	res, err := c.Encrypt(algo.LanguageLatin, "SECURITY", "HELLO")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "32 12 35 35 42"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt(algo.LanguageLatin, "SECURITY", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "HELLO" {
		t.Fatalf("Decrypt = %q, want %q", plain, "HELLO")
	}
}

func TestControlVectorPolybiusRowShiftUkrainian(t *testing.T) {
	c := algo.NewPolybiusRowShiftCipher()

	res, err := c.Encrypt(algo.LanguageUkrainian, "БЕЗПЕКА", "СЛАВА")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "ЧТЖИЖ"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt(algo.LanguageUkrainian, "БЕЗПЕКА", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "СЛАВА" {
		t.Fatalf("Decrypt = %q, want %q", plain, "СЛАВА")
	}
}

func TestControlVectorPolybiusRowShiftLatin(t *testing.T) {
	c := algo.NewPolybiusRowShiftCipher()

	res, err := c.Encrypt(algo.LanguageLatin, "SECURITY", "HELLO")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "OYVVZ"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt(algo.LanguageLatin, "SECURITY", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "HELLO" {
		t.Fatalf("Decrypt = %q, want %q", plain, "HELLO")
	}
}

// The lab's PDF renders this vector's ciphertext as "ФМІГД ЦЛФБНРЇ". Hand
// derivation from the section 4.7 formula (m=33, key digits 3,1,4,1,5
// applied cyclically to letters only, space preserved and not consuming a
// digit) gives "ФМҐГД ЦЛФБНРЇ": the third letter is 'А'+4 = index 4 = 'Ґ',
// not the visually similar 'І' the PDF shows — the same single-glyph OCR
// artifact already documented for lab 1's control vectors. Every other
// character of both halves matches the PDF exactly.
func TestControlVectorGronsfeldUkrainian(t *testing.T) {
	c := algo.NewGronsfeldCipher()

	res, err := c.Encrypt(algo.LanguageUkrainian, "31415", "СЛАВА УКРАЇНІ")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "ФМҐГД ЦЛФБНРЇ"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt(algo.LanguageUkrainian, "31415", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "СЛАВА УКРАЇНІ" {
		t.Fatalf("round-trip = %q, want %q", plain, "СЛАВА УКРАЇНІ")
	}
}

func TestControlVectorGronsfeldLatin(t *testing.T) {
	c := algo.NewGronsfeldCipher()

	res, err := c.Encrypt(algo.LanguageLatin, "2718", "HELLO WORLD")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	const want = "JLMTQ DPZNK"
	if res.Text != want {
		t.Fatalf("Encrypt = %q, want %q", res.Text, want)
	}

	plain, err := c.Decrypt(algo.LanguageLatin, "2718", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != "HELLO WORLD" {
		t.Fatalf("Decrypt = %q, want %q", plain, "HELLO WORLD")
	}
}

// --- Square construction (section 4.3, 6.2) --------------------------------

func TestBuildSquareMatchesSpecExample(t *testing.T) {
	sq, err := algo.BuildSquare(algo.LanguageUkrainian, "БЕЗПЕКА")
	if err != nil {
		t.Fatalf("BuildSquare: %v", err)
	}
	want := [algo.SquareDim]string{
		"Б Е З П К А",
		"В Г Ґ Д Є Ж",
		"И І Ї Й Л М",
		"Н О Р С Т У",
		"Ф Х Ц Ч Ш Щ",
		"Ь Ю Я 0 1 2",
	}
	for row := 1; row <= algo.SquareDim; row++ {
		var got []rune
		for col := 1; col <= algo.SquareDim; col++ {
			r, ok := sq.At(row, col)
			if !ok {
				t.Fatalf("At(%d,%d) missing", row, col)
			}
			got = append(got, r)
			if col < algo.SquareDim {
				got = append(got, ' ')
			}
		}
		if string(got) != want[row-1] {
			t.Fatalf("row %d = %q, want %q", row, string(got), want[row-1])
		}
	}
}

func TestSquareHas36UniqueSymbols(t *testing.T) {
	sq, err := algo.BuildSquare(algo.LanguageLatin, "SECURITY")
	if err != nil {
		t.Fatalf("BuildSquare: %v", err)
	}
	seen := make(map[rune]bool)
	for row := 1; row <= algo.SquareDim; row++ {
		for col := 1; col <= algo.SquareDim; col++ {
			r, ok := sq.At(row, col)
			if !ok {
				t.Fatalf("At(%d,%d) missing", row, col)
			}
			if seen[r] {
				t.Fatalf("duplicate symbol %q in square", r)
			}
			seen[r] = true
		}
	}
	if len(seen) != 36 {
		t.Fatalf("square has %d unique symbols, want 36", len(seen))
	}
}

// --- Reversibility: D_k(E_k(x)) == x for >=10 messages per mode -----------

func TestReversibilityAllModes(t *testing.T) {
	uaMessages := []string{
		"ПРИВІТСВІТЕ",
		"ҐАВАЇЖАКЄВРОІКС",
		"ОДИНДВАТРИЧОТИРИ",
		"КРИПТОГРАФІЯТАБЕЗПЕКА",
		"ЛАБОРАТОРНАРОБОТА",
		"ШИФРПІДСТАНОВКИ",
		"УКРАЇНСЬКИЙАЛФАВІТ",
		"ТЕСТУВАННЯПРОГРАМИ",
		"НОРМАЛІЗАЦІЯЮНІКОД",
		"КВАДРАТПОЛІБІЯ",
	}
	t.Run("polybius_coordinates_ua", func(t *testing.T) {
		c := algo.NewPolybiusCoordinatesCipher()
		for _, msg := range uaMessages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt(algo.LanguageUkrainian, "БЕЗПЕКА", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt(algo.LanguageUkrainian, "БЕЗПЕКА", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})

	t.Run("polybius_row_shift_ua", func(t *testing.T) {
		c := algo.NewPolybiusRowShiftCipher()
		for _, msg := range uaMessages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt(algo.LanguageUkrainian, "БЕЗПЕКА", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt(algo.LanguageUkrainian, "БЕЗПЕКА", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})

	t.Run("gronsfeld_ua", func(t *testing.T) {
		c := algo.NewGronsfeldCipher()
		for _, msg := range uaMessages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt(algo.LanguageUkrainian, "31415", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt(algo.LanguageUkrainian, "31415", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})

	latMessages := []string{
		"HELLOWORLD",
		"ABRACADABRA",
		"THEQUICKBROWNFOX",
		"SECURITYMATTERS",
		"POLYBIUSSQUARE",
		"GRONSFELDCIPHER",
		"CRYPTOGRAPHYISFUN",
		"ZEBRAXRAYQUARTZ",
		"TESTVECTORONE",
		"ANOTHERTESTCASE",
	}
	t.Run("gronsfeld_lat", func(t *testing.T) {
		c := algo.NewGronsfeldCipher()
		for _, msg := range latMessages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt(algo.LanguageLatin, "2718", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt(algo.LanguageLatin, "2718", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})

	t.Run("polybius_coordinates_lat", func(t *testing.T) {
		c := algo.NewPolybiusCoordinatesCipher()
		for _, msg := range latMessages {
			prepared := algo.Prepare(msg)
			res, err := c.Encrypt(algo.LanguageLatin, "SECURITY", msg)
			if err != nil {
				t.Fatalf("Encrypt(%q): %v", msg, err)
			}
			plain, err := c.Decrypt(algo.LanguageLatin, "SECURITY", res)
			if err != nil {
				t.Fatalf("Decrypt(%q): %v", msg, err)
			}
			if plain != prepared {
				t.Fatalf("round-trip(%q) = %q, want %q", msg, plain, prepared)
			}
		}
	})
}

// --- Ukrainian/Latin special letters ---------------------------------------

func TestUkrainianSpecialLettersInSquare(t *testing.T) {
	for _, r := range []rune{'Ґ', 'Є', 'І', 'Ї'} {
		base, err := algo.SquareBase(algo.LanguageUkrainian)
		if err != nil {
			t.Fatalf("SquareBase: %v", err)
		}
		if !base.Contains(r) {
			t.Fatalf("%q must belong to the Ukrainian square base", r)
		}
	}
}

func TestLatinEdgeLettersInAlphabet(t *testing.T) {
	letters, err := algo.Letters(algo.LanguageLatin)
	if err != nil {
		t.Fatalf("Letters: %v", err)
	}
	for _, r := range []rune{'A', 'Z'} {
		if !letters.Contains(r) {
			t.Fatalf("%q must belong to the Latin alphabet", r)
		}
	}
}

// --- Row-shift cyclic boundary (section 8 "Циклічність") -------------------

func TestRowShiftCyclesAcrossEdges(t *testing.T) {
	sq, err := algo.BuildSquare(algo.LanguageUkrainian, "БЕЗПЕКА")
	if err != nil {
		t.Fatalf("BuildSquare: %v", err)
	}
	row6, _ := sq.At(6, 3)
	shifted, ok := sq.RowShift(row6)
	if !ok {
		t.Fatalf("RowShift(%q) missing", row6)
	}
	row1, _ := sq.At(1, 3)
	if shifted != row1 {
		t.Fatalf("RowShift from row 6 = %q, want row 1 symbol %q", shifted, row1)
	}
	back, ok := sq.RowUnshift(shifted)
	if !ok || back != row6 {
		t.Fatalf("RowUnshift(%q) = %q, want %q", shifted, back, row6)
	}
}

// --- Coordinate token validation (section 4.4, 8 "Координати") ------------

func TestCoordinateTokensFirstAndLastRow(t *testing.T) {
	sq, err := algo.BuildSquare(algo.LanguageUkrainian, "БЕЗПЕКА")
	if err != nil {
		t.Fatalf("BuildSquare: %v", err)
	}
	if _, ok := sq.At(1, 1); !ok {
		t.Fatal("At(1,1) must exist")
	}
	if _, ok := sq.At(6, 6); !ok {
		t.Fatal("At(6,6) must exist")
	}
}

// Section 4.4 lists "00, 17, 61, 67" as the invalid boundary examples. "61"
// (row 6, column 1) is actually a valid in-range token (both digits in
// [1,6]) matching the square example in section 4.3 — "71" (row 7, out of
// range) is the value that fits the stated symmetric boundary pattern
// (00=both out, 17=column out, 71=row out, 67=column out), so this is read
// as the same single-digit OCR artifact already documented for lab 1 and
// this lab's Gronsfeld vector.
func TestCoordinateInvalidTokensRejected(t *testing.T) {
	c := algo.NewPolybiusCoordinatesCipher()
	badTokens := []string{"00", "17", "71", "67", "4", "4A", "4 4", "4-4"}
	for _, tok := range badTokens {
		_, err := c.Decrypt(algo.LanguageUkrainian, "БЕЗПЕКА", algo.Result{Text: tok})
		if err == nil {
			t.Errorf("Decrypt(%q) should fail", tok)
		}
	}
}

// --- Negative cases ----------------------------------------------------

func TestNegativeEmptyKeys(t *testing.T) {
	ciphers := []algo.Cipher{
		algo.NewPolybiusCoordinatesCipher(),
		algo.NewPolybiusRowShiftCipher(),
		algo.NewGronsfeldCipher(),
	}
	for _, c := range ciphers {
		if err := c.ValidateKey(algo.LanguageUkrainian, ""); err == nil {
			t.Fatalf("%s: ValidateKey(\"\") should fail", c.Algorithm())
		}
	}
}

func TestNegativeGronsfeldKeyWithLeadingZero(t *testing.T) {
	c := algo.NewGronsfeldCipher()
	if err := c.ValidateKey(algo.LanguageUkrainian, "031415"); err != nil {
		t.Fatalf("leading-zero key should be accepted: %v", err)
	}
}

func TestNegativeGronsfeldKeyAllZeros(t *testing.T) {
	c := algo.NewGronsfeldCipher()
	if err := c.ValidateKey(algo.LanguageUkrainian, "0000"); err == nil {
		t.Fatal("expected error for all-zero digit key")
	}
}

func TestNegativeGronsfeldKeyNonDigit(t *testing.T) {
	c := algo.NewGronsfeldCipher()
	if err := c.ValidateKey(algo.LanguageUkrainian, "12a4"); err == nil {
		t.Fatal("expected error for non-digit key")
	}
}

func TestNegativeGronsfeldSingleNonZeroDigit9(t *testing.T) {
	c := algo.NewGronsfeldCipher()
	if err := c.ValidateKey(algo.LanguageUkrainian, "9"); err != nil {
		t.Fatalf("single non-zero digit key should be accepted: %v", err)
	}
}

func TestNegativeSquareKeyMissingLetter(t *testing.T) {
	_, err := algo.BuildSquare(algo.LanguageUkrainian, "012")
	if err == nil {
		t.Fatal("expected error for all-digit keyword (no letters)")
	}
}

func TestNegativeSquareKeyUnsupportedRune(t *testing.T) {
	_, err := algo.BuildSquare(algo.LanguageUkrainian, "SECRET")
	if err == nil {
		t.Fatal("expected error for Latin keyword against the Ukrainian square")
	}
}

func TestNegativeUnknownLanguage(t *testing.T) {
	_, err := algo.Letters(algo.Language("fr"))
	if err == nil {
		t.Fatal("expected error for unsupported language")
	}
	_, err = algo.SquareBase(algo.Language("fr"))
	if err == nil {
		t.Fatal("expected error for unsupported language")
	}
}

// --- Formatting: spaces, newlines, digits, punctuation (row shift & Gronsfeld) --

func TestFormattingIsPreservedRowShift(t *testing.T) {
	msg := "Рядок1,\nРядок2; тест-42!"
	c := algo.NewPolybiusRowShiftCipher()
	res, err := c.Encrypt(algo.LanguageUkrainian, "БЕЗПЕКА", msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := c.Decrypt(algo.LanguageUkrainian, "БЕЗПЕКА", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != algo.Prepare(msg) {
		t.Fatalf("round-trip = %q, want %q", plain, algo.Prepare(msg))
	}
}

func TestFormattingIsPreservedGronsfeld(t *testing.T) {
	msg := "Рядок1,\nРядок2; тест-42!"
	c := algo.NewGronsfeldCipher()
	res, err := c.Encrypt(algo.LanguageUkrainian, "31415", msg)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	plain, err := c.Decrypt(algo.LanguageUkrainian, "31415", res)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if plain != algo.Prepare(msg) {
		t.Fatalf("round-trip = %q, want %q", plain, algo.Prepare(msg))
	}
}
