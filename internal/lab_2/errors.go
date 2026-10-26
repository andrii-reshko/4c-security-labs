package lab_2

import "errors"

// ErrUnknownAlgorithm is returned by CipherService when asked for an
// Algorithm no Cipher was registered for in composition_root.go. Per-key
// validation errors live alongside the concrete cipher implementations in
// internal/lab_2_algo.
var ErrUnknownAlgorithm = errors.New("невідомий алгоритм")
