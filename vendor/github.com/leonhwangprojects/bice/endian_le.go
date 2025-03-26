//go:build 386 || amd64 || arm || arm64 || mips64le || ppc64le || riscv64 || wasm
// +build 386 amd64 arm arm64 mips64le ppc64le riscv64 wasm

// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

func h2ns(v uint16) uint16 {
	var b [2]byte
	ne.PutUint16(b[:], v)
	return be.Uint16(b[:])
}

func h2nl(v uint32) uint32 {
	var b [4]byte
	ne.PutUint32(b[:], v)
	return be.Uint32(b[:])
}

func h2nll(v uint64) uint64 {
	var b [8]byte
	ne.PutUint64(b[:], v)
	return be.Uint64(b[:])
}
