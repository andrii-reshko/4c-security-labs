package lab_1_test

import (
	"strings"
	"testing"

	algo "4c-security-labs/internal/lab_1_algo"
)

// longUkrainianText is a few hundred letters of natural-ish Ukrainian text,
// long enough for both the Kasiski and index-of-coincidence methods to have
// a realistic chance of recovering the true Vigenere key length (section 13
// explicitly calls for "достатньо довгий текст").
const longUkrainianText = `УКРАЇНСЬКА МОВА НАЛЕЖИТЬ ДО СЛОВЯНСЬКОЇ ГРУПИ МОВ І МАЄ ДОВГУ ІСТОРІЮ
РОЗВИТКУ ПИСЕМНОСТІ ТА ЛІТЕРАТУРИ. КРИПТОГРАФІЯ ВИВЧАЄ МЕТОДИ ЗАХИСТУ
ІНФОРМАЦІЇ ВІД НЕСАНКЦІОНОВАНОГО ДОСТУПУ ТА АНАЛІЗУЄ СТІЙКІСТЬ РІЗНИХ
АЛГОРИТМІВ ШИФРУВАННЯ ДО ЗЛАМУ. КЛАСИЧНІ ШИФРИ НАВЧАЛЬНІ ТА НЕ ПРИЗНАЧЕНІ
ДЛЯ ЗАХИСТУ РЕАЛЬНИХ ДАНИХ АЛЕ ДОПОМАГАЮТЬ ЗРОЗУМІТИ ОСНОВНІ ПРИНЦИПИ
ПІДСТАНОВКИ ТА ПЕРЕСТАНОВКИ СИМВОЛІВ У ПОВІДОМЛЕННІ. ШИФР ВІЖЕНЕРА Є
ПЕРІОДИЧНОЮ БАГАТОАЛФАВІТНОЮ ПІДСТАНОВКОЮ ДЕ КОЖНА ЛІТЕРА КЛЮЧА ЗАДАЄ
ОКРЕМИЙ ЗСУВ АЛФАВІТУ ДЛЯ ВІДПОВІДНОЇ ПОЗИЦІЇ ВІДКРИТОГО ТЕКСТУ І ТОМУ
КОРОТКИЙ КЛЮЧ ЩО ПОВТОРЮЄТЬСЯ БАГАТО РАЗІВ РОБИТЬ ШИФРОТЕКСТ ВРАЗЛИВИМ
ДО АНАЛІЗУ МЕТОДОМ КАСІСКІ АБО ІНДЕКСУ ЗБІГІВ ОСОБЛИВО НА ДОВГИХ ТЕКСТАХ
ДЕ ОДНАКОВІ ФРАГМЕНТИ ВІДКРИТОГО ТЕКСТУ ПОВТОРЮЮТЬСЯ НА ВІДСТАНЯХ КРАТНИХ
ДОВЖИНІ КЛЮЧА І ЦЕ ЗАЛИШАЄ ПОМІТНИЙ СЛІД У ШИФРОТЕКСТІ ЯКИЙ МОЖНА ЗНАЙТИ`

func TestEstimateVigenereKeyLength(t *testing.T) {
	const key = "КЛЮЧ" // length 4
	wantLength := len([]rune(key))

	c := algo.NewVigenereCipher("")
	res, err := c.Encrypt(key, longUkrainianText)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	t.Run("index_of_coincidence", func(t *testing.T) {
		got, scores := algo.EstimateVigenereKeyLengthByIC(res.Text, 12)
		if got != wantLength {
			t.Errorf("EstimateVigenereKeyLengthByIC = %d, want %d (scores: %v)", got, wantLength, scores)
		}
	})

	t.Run("kasiski", func(t *testing.T) {
		candidates := algo.KasiskiCandidates(res.Text, 3, 12)
		if len(candidates) == 0 {
			t.Fatal("KasiskiCandidates returned no candidates")
		}
		found := false
		for _, c := range candidates[:min(3, len(candidates))] {
			if c == wantLength {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("KasiskiCandidates top-3 = %v, want %d among them", candidates[:min(3, len(candidates))], wantLength)
		}
	})
}

func TestKasiskiCandidatesEmptyOnShortText(t *testing.T) {
	candidates := algo.KasiskiCandidates("АБВ", 3, 10)
	if len(candidates) != 0 {
		t.Fatalf("expected no candidates for text shorter than one repeat, got %v", candidates)
	}
}

func TestLongUkrainianTextFixtureIsLongEnough(t *testing.T) {
	letters := strings.Count(algo.PrepareWithMode(longUkrainianText, algo.PrepLettersOnly), "")
	if letters < 300 {
		t.Fatalf("fixture text too short for a reliable estimate: %d letters", letters)
	}
}
