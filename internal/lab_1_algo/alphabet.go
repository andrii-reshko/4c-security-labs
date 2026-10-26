package lab_1_algo

import "4c-security-labs/internal/shared"

// BaseAlphabetLetters is the standard 33-letter Ukrainian alphabet used
// throughout the lab (section 4.1). The literal lives once in
// internal/shared, shared with internal/lab_2_algo.
const BaseAlphabetLetters = shared.UkrainianLetters

// Alphabet is an ordered, indexed set of letters (position of a letter,
// letter at a position, membership test). The implementation is shared
// with internal/lab_2_algo via internal/shared — see that package for the
// methods available on it.
type Alphabet = shared.Alphabet

// DefaultAlphabet is the standard 33-letter Ukrainian alphabet (section
// 4.1), shared by every cipher in this package. It is the same instance as
// internal/shared.UkrainianAlphabet, not a separately built copy.
var DefaultAlphabet = shared.UkrainianAlphabet
