// Package shared holds code with no cryptographic logic of its own that
// multiple labs would otherwise duplicate byte-for-byte: the ordered
// rune/index set every alphabet-like structure needs, the common
// NFC-normalize-and-uppercase text preparation step, and the CLI
// boilerplate every cmd/lab_*/main.go repeats. It intentionally knows
// nothing about any specific lab's algorithms, key formats or flags.
package shared

// UkrainianLetters is the 33-letter Ukrainian alphabet both labs build
// their Ukrainian alphabet/square from (lab 1 section 4.1, lab 2 section
// 4.1 table). Kept in one place because it is a literal that must stay
// byte-for-byte identical everywhere it is used — a copy-pasted duplicate
// is one typo away from silently diverging.
const UkrainianLetters = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"

// LatinLetters is the 26-letter Latin alphabet (lab 2 section 4.1 table).
const LatinLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Alphabet is an ordered, indexed set of runes. It backs every
// alphabet-like structure a lab's ciphers need: a plain letters alphabet,
// a letters+digits square base set, a substitution table, etc. — anything
// that needs "position of a symbol", "symbol at a position" and
// "membership test" behind methods instead of raw slice/map access.
type Alphabet struct {
	runes []rune
	index map[rune]int
}

// NewAlphabet builds an Alphabet from a string of distinct symbols,
// assigning each one its position (0-based) as index. Callers are
// responsible for passing distinct runes; a repeated rune simply keeps the
// index of its last occurrence.
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

// String returns the alphabet's symbols as a single string, in order.
func (a *Alphabet) String() string {
	return string(a.runes)
}

// UkrainianAlphabet and LatinAlphabet are the ready-built, package-level
// Alphabet instances for the two letters-only alphabets every lab uses.
// They are built once here, at package init, and shared by reference —
// lab_1_algo's DefaultAlphabet and lab_2_algo's Letters(LanguageUkrainian)
// are literally this same *Alphabet, not two separately constructed
// equal-but-distinct copies, and no cipher call rebuilds the rune/index
// set on every Encrypt/Decrypt (section 10, "Продуктивність: таблиці
// пошуку готуються один раз").
var (
	UkrainianAlphabet = NewAlphabet(UkrainianLetters)
	LatinAlphabet     = NewAlphabet(LatinLetters)
)
