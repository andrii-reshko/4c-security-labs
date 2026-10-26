package lab_2_algo

import (
	"fmt"
	"strings"
)

// SquareDim is the side of the key square (section 4.1: "таблицю 6 на 6").
const SquareDim = 6

// Square is the 6x6 key table from section 4.3, plus the forward
// (symbol -> coordinates) and reverse (coordinates -> symbol) lookup built
// once right after construction, not recomputed per character (section 6.4
// pseudocode, section 10 "Продуктивність").
type Square struct {
	lang    Language
	table   [SquareDim][SquareDim]rune
	toCoord map[rune][2]int // 1-based [row, col]
	toRune  map[[2]int]rune
}

// BuildSquare turns keyword into the 6x6 table described in section 4.3:
// normalize to NFC, upper-case, verify every symbol belongs to lang's
// square base and that at least one is a letter; drop repeated symbols
// keeping the first occurrence; append every unused base symbol in base
// order. The result must contain exactly 36 unique symbols (section 6.2).
func BuildSquare(lang Language, keyword string) (*Square, error) {
	base, err := SquareBase(lang)
	if err != nil {
		return nil, err
	}
	letters, err := Letters(lang)
	if err != nil {
		return nil, err
	}

	prepared := Prepare(keyword)
	if prepared == "" {
		return nil, ErrEmptyKey
	}

	seen := make(map[rune]bool, base.Size())
	sequence := make([]rune, 0, base.Size())
	hasLetter := false
	for _, r := range prepared {
		if !base.Contains(r) {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedRune, r)
		}
		if letters.Contains(r) {
			hasLetter = true
		}
		if seen[r] {
			continue
		}
		seen[r] = true
		sequence = append(sequence, r)
	}
	if !hasLetter {
		return nil, ErrKeyMissingLetter
	}
	for _, r := range base.Runes() {
		if !seen[r] {
			seen[r] = true
			sequence = append(sequence, r)
		}
	}
	if len(sequence) != base.Size() {
		return nil, fmt.Errorf("%w: отримано %d символів", ErrSquareWrongSize, len(sequence))
	}

	sq := &Square{
		lang:    lang,
		toCoord: make(map[rune][2]int, len(sequence)),
		toRune:  make(map[[2]int]rune, len(sequence)),
	}
	for i, r := range sequence {
		row, col := i/SquareDim, i%SquareDim
		sq.table[row][col] = r
		coord := [2]int{row + 1, col + 1}
		sq.toCoord[r] = coord
		sq.toRune[coord] = r
	}
	return sq, nil
}

// At returns the symbol at 1-based (row, col).
func (s *Square) At(row, col int) (rune, bool) {
	r, ok := s.toRune[[2]int{row, col}]
	return r, ok
}

// Coordinates returns the 1-based (row, col) of r, if r belongs to the
// square (section 4.4).
func (s *Square) Coordinates(r rune) ([2]int, bool) {
	c, ok := s.toCoord[r]
	return c, ok
}

// Contains reports whether r belongs to the square.
func (s *Square) Contains(r rune) bool {
	_, ok := s.toCoord[r]
	return ok
}

// RowShift returns the symbol one row below r in the same column, cycling
// from row 6 back to row 1 (section 4.5).
func (s *Square) RowShift(r rune) (rune, bool) {
	coord, ok := s.toCoord[r]
	if !ok {
		return 0, false
	}
	nextRow := coord[0]%SquareDim + 1
	out, _ := s.At(nextRow, coord[1])
	return out, true
}

// RowUnshift is the inverse of RowShift: the symbol one row above r in the
// same column, cycling from row 1 back to row 6.
func (s *Square) RowUnshift(r rune) (rune, bool) {
	coord, ok := s.toCoord[r]
	if !ok {
		return 0, false
	}
	prevRow := coord[0] - 2
	if prevRow < 0 {
		prevRow += SquareDim
	}
	out, _ := s.At(prevRow+1, coord[1])
	return out, true
}

// String renders the square as a 6x6 grid, one space-separated row per
// line — used to show the "активний квадрат" the recommended interface
// calls for (section 6.3).
func (s *Square) String() string {
	var b strings.Builder
	for row := 1; row <= SquareDim; row++ {
		if row > 1 {
			b.WriteByte('\n')
		}
		for col := 1; col <= SquareDim; col++ {
			if col > 1 {
				b.WriteByte(' ')
			}
			r, _ := s.At(row, col)
			b.WriteRune(r)
		}
	}
	return b.String()
}
