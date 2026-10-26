package lab_2_algo

import "fmt"

// Language selects which base character set an algorithm run against
// (section 4.1, "Узгоджені набори символів"). It must always be passed
// explicitly — automatic language guessing is disallowed (section 5,
// "Вибір мови").
type Language string

const (
	LanguageUkrainian Language = "ua"
	LanguageLatin     Language = "lat"
)

// UkrainianLetters is the 33-letter Ukrainian alphabet (section 4.1).
const UkrainianLetters = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"

// LatinLetters is the 26-letter Latin alphabet (section 4.1).
const LatinLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// ukrainianSquareDigits and latinSquareDigits are appended after the
// letters, in ascending order, to build the 36-symbol square base set
// (section 4.1 table).
const ukrainianSquareDigits = "012"
const latinSquareDigits = "0123456789"

// Alphabet is an ordered, indexed set of runes. It backs both the
// letters-only alphabet the Gronsfeld cipher advances over and the
// 36-symbol base set the Polybius square is built from.
type Alphabet struct {
	runes []rune
	index map[rune]int
}

// NewAlphabet builds an Alphabet from a string of distinct symbols,
// assigning each one its position (0-based) as index.
func NewAlphabet(symbols string) *Alphabet {
	runes := []rune(symbols)
	index := make(map[rune]int, len(runes))
	for i, r := range runes {
		index[r] = i
	}
	return &Alphabet{runes: runes, index: index}
}

// Size returns m, the power of the alphabet.
func (a *Alphabet) Size() int {
	return len(a.runes)
}

// IndexOf returns the position of r in the alphabet and true if r belongs
// to it.
func (a *Alphabet) IndexOf(r rune) (int, bool) {
	i, ok := a.index[r]
	return i, ok
}

// RuneAt returns the symbol at position i (0 <= i < Size()).
func (a *Alphabet) RuneAt(i int) rune {
	return a.runes[i]
}

// Contains reports whether r is one of the alphabet's symbols.
func (a *Alphabet) Contains(r rune) bool {
	_, ok := a.index[r]
	return ok
}

// Runes returns a copy of the alphabet's symbols in order; callers may
// freely mutate the result without affecting the Alphabet.
func (a *Alphabet) Runes() []rune {
	out := make([]rune, len(a.runes))
	copy(out, a.runes)
	return out
}

// Letters returns the base, letters-only alphabet for lang, used by the
// Gronsfeld cipher (section 4.7: "Базові алфавіти для Гронсфельда містять
// лише літери").
func Letters(lang Language) (*Alphabet, error) {
	switch lang {
	case LanguageUkrainian:
		return NewAlphabet(UkrainianLetters), nil
	case LanguageLatin:
		return NewAlphabet(LatinLetters), nil
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
		return NewAlphabet(UkrainianLetters + ukrainianSquareDigits), nil
	case LanguageLatin:
		return NewAlphabet(LatinLetters + latinSquareDigits), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownLanguage, lang)
	}
}
