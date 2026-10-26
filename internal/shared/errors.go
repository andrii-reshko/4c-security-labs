package shared

import "errors"

// ErrUnknownAlgorithm is returned by a lab's CipherService.Get when asked
// for an Algorithm no Cipher was registered for in composition_root.go.
// Both labs' dispatch errors share this one message/identity so that
// errors.Is works the same way regardless of which lab produced the error.
var ErrUnknownAlgorithm = errors.New("невідомий алгоритм")

// ErrEmptyKey is returned by key validation in both labs when the supplied
// key is empty — the same message/identity for every cipher in either lab.
var ErrEmptyKey = errors.New("ключ не може бути порожнім")
