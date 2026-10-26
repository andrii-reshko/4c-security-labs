package lab_1_algo

import "errors"

// Sentinel errors returned by key validation and by the ciphers themselves.
// They are wrapped with extra context via fmt.Errorf("%w: ...") where useful,
// so callers can still match on them with errors.Is. ErrEmptyKey lives in
// internal/shared — see that package's errors.go — since the message is
// identical across every cipher in both labs.
var (
	ErrUnsupportedRune   = errors.New("символ не підтримується базовим алфавітом")
	ErrDuplicateLetter   = errors.New("ключ містить літеру, що повторюється у таблиці підстановки")
	ErrTableWrongLength  = errors.New("таблиця підстановки має хибну довжину")
	ErrNotAPermutation   = errors.New("ключ не є перестановкою чисел від 1 до n без повторів")
	ErrPaddingOutOfRange = errors.New("кількість доданих символів виходить за межі довжини блока")
)
