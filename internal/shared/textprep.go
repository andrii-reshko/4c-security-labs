package shared

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Prepare normalizes text to Unicode NFC and upper-cases it — the first,
// mandatory step of every lab's "Єдина специфікація обробки тексту"
// (кодування, нормалізація, регістр). Spaces, digits and punctuation are
// left untouched by this step; whether they survive into a cipher's output
// depends on that cipher's own mode.
func Prepare(text string) string {
	return strings.ToUpper(norm.NFC.String(text))
}
