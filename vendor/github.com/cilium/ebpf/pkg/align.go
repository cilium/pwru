package pkg

// Align returns 'n' updated to 'alignment' boundary.
func Align(n, alignment int) int {
	return (int(n) + alignment - 1) / alignment * alignment
}
