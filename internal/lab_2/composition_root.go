package lab_2

import (
	algo "4c-security-labs/internal/lab_2_algo"
	"4c-security-labs/internal/shared"
)

// Container holds this lab's CipherService; see internal/shared.Container
// for why the wrapper itself is shared across labs.
type Container = shared.Container[*CipherService]

func NewContainer() *Container {
	service := NewCipherService(
		algo.NewPolybiusCoordinatesCipher(),
		algo.NewPolybiusRowShiftCipher(),
		algo.NewGronsfeldCipher(),
	)
	return shared.NewContainer(service)
}
