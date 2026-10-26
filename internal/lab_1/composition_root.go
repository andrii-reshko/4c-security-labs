package lab_1

import (
	algo "4c-security-labs/internal/lab_1_algo"
	"4c-security-labs/internal/shared"
)

// Container holds this lab's CipherService; see internal/shared.Container
// for why the wrapper itself is shared across labs.
type Container = shared.Container[*CipherService]

func NewContainer() *Container {
	conf := Configure()

	service := NewCipherService(
		algo.NewSubstitutionCipher(conf.Keys.Substitution),
		algo.NewVigenereCipher(conf.Keys.Vigenere),
		algo.NewBlockPermutationCipher(conf.Keys.BlockPermutation),
		algo.NewColumnarCipher(conf.Keys.Columnar),
		algo.NewHomophonicCipher(conf.Keys.Homophonic),
	)
	return shared.NewContainer(service)
}
