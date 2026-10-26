package lab_2_algo

import "errors"

// Sentinel errors returned by key/text validation and by the ciphers
// themselves. They are wrapped with extra context via fmt.Errorf("%w: ...")
// where useful, so callers can still match on them with errors.Is.
// ErrEmptyKey lives in internal/shared — see that package's errors.go —
// since the message is identical across every cipher in both labs.
var (
	ErrUnknownLanguage  = errors.New("невідома мова/алфавіт")
	ErrUnsupportedRune  = errors.New("символ не підтримується обраним набором")
	ErrKeyMissingLetter = errors.New("ключове слово має містити щонайменше одну літеру")
	ErrSquareWrongSize  = errors.New("квадрат має хибний розмір")
	ErrInvalidToken     = errors.New("некоректний координатний токен")
	ErrInvalidDigitKey  = errors.New("цифровий ключ має містити лише цифри")
	ErrDigitKeyAllZeros = errors.New("цифровий ключ не може складатися лише з нулів")
)
