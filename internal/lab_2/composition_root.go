package lab_2

import algo "4c-security-labs/internal/lab_2_algo"

type Container struct {
	Service *CipherService
}

func NewContainer() *Container {
	service := NewCipherService(
		algo.NewPolybiusCoordinatesCipher(),
		algo.NewPolybiusRowShiftCipher(),
		algo.NewGronsfeldCipher(),
	)
	return &Container{
		Service: service,
	}
}
