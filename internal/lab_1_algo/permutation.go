package lab_1_algo

import (
	"fmt"
	"strconv"
	"strings"

	"4c-security-labs/internal/shared"
)

// parsePermutation reads a permutation key such as "3 2 5 1 4" or "3,2,5,1,4"
// or the compact single-digit form "32514" into zero-based Go indices, and
// validates it against the section 6.2 rule: every number from 1 to n
// appears exactly once.
func parsePermutation(key string) ([]int, error) {
	fields := strings.FieldsFunc(key, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';' || r == '\t' || r == '\n'
	})

	var numbers []int
	if len(fields) > 1 || (len(fields) == 1 && len(fields[0]) == 1) {
		for _, f := range fields {
			n, err := strconv.Atoi(f)
			if err != nil {
				return nil, fmt.Errorf("%w: %q не є числом", ErrNotAPermutation, f)
			}
			numbers = append(numbers, n)
		}
	} else if len(fields) == 1 {
		// Compact form: every digit is its own position, e.g. "32514".
		for _, r := range fields[0] {
			n, err := strconv.Atoi(string(r))
			if err != nil {
				return nil, fmt.Errorf("%w: %q не є числом", ErrNotAPermutation, string(r))
			}
			numbers = append(numbers, n)
		}
	}

	if len(numbers) == 0 {
		return nil, shared.ErrEmptyKey
	}

	n := len(numbers)
	seen := make([]bool, n+1)
	indices := make([]int, n)
	for i, v := range numbers {
		if v < 1 || v > n || seen[v] {
			return nil, fmt.Errorf("%w: довжина %d, отримано %v", ErrNotAPermutation, n, numbers)
		}
		seen[v] = true
		indices[i] = v - 1
	}
	return indices, nil
}

// inversePermutation computes perm^-1 such that applying perm then
// inversePermutation(perm) restores the original order.
func inversePermutation(perm []int) []int {
	inv := make([]int, len(perm))
	for i, p := range perm {
		inv[p] = i
	}
	return inv
}
