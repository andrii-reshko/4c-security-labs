package shared

// Container is the single-field dependency holder every lab's
// composition_root.go builds: it exists purely so cmd/lab_*/main.go has
// one place (app.Service) to reach the lab's CipherService through,
// instead of constructing it inline. S is each lab's own *CipherService
// type (they are not interchangeable — lab 2's Cipher interface takes an
// extra Language parameter — so this only shares the wrapper shape, not
// any dispatch logic).
type Container[S any] struct {
	Service S
}

// NewContainer wraps service in a Container.
func NewContainer[S any](service S) *Container[S] {
	return &Container[S]{Service: service}
}
