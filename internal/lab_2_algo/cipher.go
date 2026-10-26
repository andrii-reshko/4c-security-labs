package lab_2_algo

import "4c-security-labs/internal/shared"

// Algorithm identifies one of the three mandatory modes (section 6.1).
type Algorithm string

const (
	AlgorithmPolybiusCoordinates Algorithm = "polybius_coordinates"
	AlgorithmPolybiusRowShift    Algorithm = "polybius_row_shift"
	AlgorithmGronsfeld           Algorithm = "gronsfeld"
)

// Algorithms lists every supported algorithm in a stable, UI-friendly order.
var Algorithms = []Algorithm{
	AlgorithmPolybiusCoordinates,
	AlgorithmPolybiusRowShift,
	AlgorithmGronsfeld,
}

// Label returns a human-readable Ukrainian name for the algorithm.
func (a Algorithm) Label() string {
	switch a {
	case AlgorithmPolybiusCoordinates:
		return "Квадрат Полібія — координатний режим"
	case AlgorithmPolybiusRowShift:
		return "Квадрат Полібія — циклічний зсув за рядками"
	case AlgorithmGronsfeld:
		return "Шифр Гронсфельда"
	default:
		return string(a)
	}
}

// Result is what every cipher returns from Encrypt. The implementation is
// shared with internal/lab_1_algo via internal/shared; lab 2's ciphers
// never populate Meta.
type Result = shared.Result

// Cipher is the shared, interface-only contract between the cryptographic
// core and any delivery mechanism (CLI, tests). lang is explicit on every
// call — section 5 ("Вибір мови") disallows guessing it from the text.
type Cipher interface {
	Algorithm() Algorithm
	ValidateKey(lang Language, key string) error
	Encrypt(lang Language, key, plaintext string) (Result, error)
	Decrypt(lang Language, key string, in Result) (string, error)
}
