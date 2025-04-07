// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bice

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

type InjectOptions struct {
	Prog     *ebpf.ProgramSpec
	StubFunc string
	Expr     string
	Type     btf.Type
}

func findStubFunc(prog *ebpf.ProgramSpec, stubFunc string) (int, bool) {
	for idx, inst := range prog.Instructions {
		if inst.Symbol() == stubFunc {
			return idx, true
		}
	}
	return -1, false
}

func findRetInsn(prog *ebpf.ProgramSpec, idx int) (int, bool) {
	for i := idx + 1; i < len(prog.Instructions); i++ {
		if prog.Instructions[i].OpCode == asm.Return().OpCode {
			return i, true
		}
	}
	return -1, false
}

func inject(opts InjectOptions, insns asm.Instructions) error {
	prog := opts.Prog

	startIdx, found := findStubFunc(prog, opts.StubFunc)
	if !found {
		return fmt.Errorf("cannot find the stub function(%s): %w", opts.StubFunc, ErrNotFound)
	}

	returnIdx, found := findRetInsn(prog, startIdx)
	if !found {
		return fmt.Errorf("cannot find the return insn of the stub function(%s): %w", opts.StubFunc, ErrNotFound)
	}

	insns[0] = insns[0].WithMetadata(prog.Instructions[startIdx].Metadata)
	prog.Instructions = append(prog.Instructions[:startIdx],
		append(insns, prog.Instructions[returnIdx+1:]...)...) // replace the original insns with the new ones

	return nil
}
