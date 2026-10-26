package lab_1_algo

// BaseAlphabetLetters is the standard 33-letter Ukrainian alphabet used
// throughout the lab (section 4.1).
const BaseAlphabetLetters = "АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ"

// Alphabet is an ordered, indexed set of letters. It encapsulates the
// rune-slice/index-map pair every cipher needs (position of a letter,
// letter at a position, membership test) behind methods, instead of each
// cipher reaching into package-level globals directly.
type Alphabet struct {
	letters []rune
	index   map[rune]int
}

// NewAlphabet builds an Alphabet from a string of letters, assigning each
// one its position (0-based) as index. Callers are responsible for passing
// distinct runes; a repeated rune simply keeps the index of its last
// occurrence.
func NewAlphabet(letters string) *Alphabet {
	runes := []rune(letters)
	index := make(map[rune]int, len(runes))
	for i, r := range runes {
		index[r] = i
	}
	return &Alphabet{letters: runes, index: index}
}

// DefaultAlphabet is the standard 33-letter Ukrainian alphabet (section
// 4.1), shared by every cipher in this package.
var DefaultAlphabet = NewAlphabet(BaseAlphabetLetters)

// Size returns m, the power of the alphabet.
func (a *Alphabet) Size() int {
	return len(a.letters)
}

// IndexOf returns the position of r in the alphabet and true if r belongs
// to it.
func (a *Alphabet) IndexOf(r rune) (int, bool) {
	i, ok := a.index[r]
	return i, ok
}

// RuneAt returns the letter at position i (0 <= i < Size()).
func (a *Alphabet) RuneAt(i int) rune {
	return a.letters[i]
}

// Contains reports whether r is one of the alphabet's letters.
func (a *Alphabet) Contains(r rune) bool {
	_, ok := a.index[r]
	return ok
}

// Runes returns a copy of the alphabet's letters in order; callers may
// freely mutate the result without affecting the Alphabet.
func (a *Alphabet) Runes() []rune {
	out := make([]rune, len(a.letters))
	copy(out, a.letters)
	return out
}

// String returns the alphabet's letters as a single string, in order.
func (a *Alphabet) String() string {
	return string(a.letters)
}
