package mybtf

import "github.com/cilium/ebpf/btf"

type bitsInfo struct {
	offset btf.Bits
	size   btf.Bits
}

var emptyBits = bitsInfo{}

func intOffset(v btf.Bits) btf.Bits {
	return (v & 0x00ff0000) >> 16
}

func intBits(v btf.Bits) btf.Bits {
	return v & 0x000000ff
}

func shiftInt128(int128 []byte, leftShiftBits, rightShiftBits uint32) (lo, hi uint64) {
	lo, hi = ne.Uint64(int128[:8]), ne.Uint64(int128[8:])

	if leftShiftBits >= 64 {
		hi = lo << (leftShiftBits - 64)
		lo = 0
	} else {
		hi = (hi << leftShiftBits) | (lo >> (64 - leftShiftBits))
		lo <<= leftShiftBits
	}

	if rightShiftBits >= 64 {
		lo = hi >> (rightShiftBits - 64)
		hi = 0
	} else {
		lo = (lo >> rightShiftBits) | (hi << (64 - rightShiftBits))
		hi >>= rightShiftBits
	}

	return
}
