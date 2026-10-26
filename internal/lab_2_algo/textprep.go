package lab_2_algo

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Prepare normalizes text to Unicode NFC and upper-cases it (section 5:
// "Кодування", "Нормалізація", "Регістр"). Spaces, digits (outside the
// square base set) and punctuation are left untouched by this step; whether
// they survive into the output depends on the specific cipher/mode.
func Prepare(text string) string {
	return strings.ToUpper(norm.NFC.String(text))
}
