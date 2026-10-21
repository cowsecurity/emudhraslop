package cache

// Historical reports require an owner-private file boundary. The Windows
// scanner deliberately has no cache ACL implementation, so this fails closed.
func readObservation(string) ([]byte, error) { return nil, ErrInvalid }
