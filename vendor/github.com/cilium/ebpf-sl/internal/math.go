package internal

// Align returns 'n' updated to 'alignment' boundary.
func Align[I Integer](n, alignment I) I {
	return (n + alignment - 1) / alignment * alignment
}

// Between returns the value clamped between a and b.
func Between[I Integer](val, a, b I) I {
	lower, upper := a, b
	if lower > upper {
		upper, lower = a, b
	}

	val = min(val, upper)
	return max(val, lower)
}

// Integer represents all possible integer types.
// Remove when x/exp/constraints is moved to the standard library.
type Integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}
