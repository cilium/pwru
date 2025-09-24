// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */
/* Copyright 2025 Leon Hwang */

package pwru

import (
	"encoding/binary"

	"github.com/cilium/ebpf"
)

// The following genEndbrPoison() and isEndbrInsn() functions are taken from the
// kernel's arch/x86/include/asm/ibt.h file.

func genEndbrPoison() uint32 {
	// 4 byte NOP that isn't NOP4 (in fact it is OSP NOP3), such that it
	// will be unique to (former) ENDBR sites.
	return 0x001f0f66 /* osp nopl (%rax) */
}

func isEndbrInsn(val uint32) bool {
	const endbr64 uint32 = 0xfa1e0ff3

	if val == genEndbrPoison() {
		return true
	}

	val &= ^uint32(0x01000000) /* ENDBR32 -> ENDBR64 */
	return val == endbr64
}

func haveEndbrInsn(prog *ebpf.Program) (bool, error) {
	info, err := prog.Info()
	if err != nil {
		return false, err
	}

	jitedInsns, ok := info.JitedInsns()
	if !ok || len(jitedInsns) < 4 {
		return false, nil
	}

	u32 := binary.NativeEndian.Uint32(jitedInsns[:4])
	return isEndbrInsn(u32), nil
}
