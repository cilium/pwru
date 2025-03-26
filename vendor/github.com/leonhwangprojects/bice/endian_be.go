//go:build armbe || arm64be || mips || mips64 || ppc64
// +build armbe arm64be mips mips64 ppc64

// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

func h2ns(v uint16) uint16  { return v }
func h2nl(v uint32) uint32  { return v }
func h2nll(v uint64) uint64 { return v }
