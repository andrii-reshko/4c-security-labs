package lab_1

import algo "4c-security-labs/internal/lab_1_algo"

type Container struct {
	Service *CipherService
}

func NewContainer() *Container {
	conf := Configure()

	service := NewCipherService(
		algo.NewSubstitutionCipher(conf.Keys.Substitution),
		algo.NewVigenereCipher(conf.Keys.Vigenere),
		algo.NewBlockPermutationCipher(conf.Keys.BlockPermutation),
		algo.NewColumnarCipher(conf.Keys.Columnar),
		algo.NewHomophonicCipher(conf.Keys.Homophonic),
	)
	return &Container{
		Service: service,
	}
}
