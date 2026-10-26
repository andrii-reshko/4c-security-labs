package lab_2_algo

import (
	"fmt"

	"4c-security-labs/internal/shared"
)

// Language selects which base character set an algorithm run against
// (section 4.1, "Узгоджені набори символів"). It must always be passed
// explicitly — automatic language guessing is disallowed (section 5,
// "Вибір мови").
type Language string

const (
	LanguageUkrainian Language = "ua"
	LanguageLatin     Language = "lat"
)

// UkrainianLetters is the 33-letter Ukrainian alphabet (section 4.1). The
// literal lives once in internal/shared, shared with internal/lab_1_algo.
const UkrainianLetters = shared.UkrainianLetters

// LatinLetters is the 26-letter Latin alphabet (section 4.1). The literal
// lives once in internal/shared.
const LatinLetters = shared.LatinLetters

// ukrainianSquareDigits and latinSquareDigits are appended after the
// letters, in ascending order, to build the 36-symbol square base set
// (section 4.1 table).
const ukrainianSquareDigits = "012"
const latinSquareDigits = "0123456789"

// Alphabet is an ordered, indexed set of runes. It backs both the
// letters-only alphabet the Gronsfeld cipher advances over and the
// 36-symbol base set the Polybius square is built from. The implementation
// is shared with internal/lab_1_algo via internal/shared.
type Alphabet = shared.Alphabet

// ukrainianSquareBase and latinSquareBase are built once at package init,
// not on every BuildSquare call — the symbol set is fixed, so there is
// nothing to recompute (section 10, "Продуктивність: таблиці пошуку
// готуються один раз").
var (
	ukrainianSquareBase = shared.NewAlphabet(UkrainianLetters + ukrainianSquareDigits)
	latinSquareBase     = shared.NewAlphabet(LatinLetters + latinSquareDigits)
)

// Letters returns the base, letters-only alphabet for lang, used by the
// Gronsfeld cipher (section 4.7: "Базові алфавіти для Гронсфельда містять
// лише літери"). For LanguageUkrainian this is the exact same *Alphabet
// instance as internal/shared.UkrainianAlphabet (and lab_1_algo's
// DefaultAlphabet) — not a fresh copy built per call.
func Letters(lang Language) (*Alphabet, error) {
	switch lang {
	case LanguageUkrainian:
		return shared.UkrainianAlphabet, nil
	case LanguageLatin:
		return shared.LatinAlphabet, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownLanguage, lang)
	}
}

// SquareBase returns the 36-symbol base set for lang: the letters in
// alphabet order, followed by the digits in ascending order (section 4.1
// table).
func SquareBase(lang Language) (*Alphabet, error) {
	switch lang {
	case LanguageUkrainian:
		return ukrainianSquareBase, nil
	case LanguageLatin:
		return latinSquareBase, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownLanguage, lang)
	}
}
