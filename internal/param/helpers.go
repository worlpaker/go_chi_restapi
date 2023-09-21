package param

// IsNull checks whether any of the given parameters is an empty string
func IsNull(m ...string) (ok bool) {
	for i := range m {
		if m[i] == "" {
			ok = true
			return
		}
	}
	return
}
