// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */
/* Copyright Authors of Cilium */

package libcc

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const (
	stubFuncSkb = "filter_skb_expr"
	stubFuncXdp = "filter_xdp_expr"
)

type compileFunc func(string, *btf.Spec) (asm.Instructions, error)

func injectFilter(spec *btf.Spec, prog *ebpf.ProgramSpec, filterExpr, stubFunc string, compile compileFunc) error {
	if filterExpr == "" {
		return nil
	}

	injectIdx := -1
	for idx, inst := range prog.Instructions {
		if inst.Symbol() == stubFunc {
			injectIdx = idx
			break
		}
	}
	if injectIdx == -1 {
		return errors.New("cannot find the injection position")
	}

	retInsnIdx := -1
	for idx := injectIdx + 1; idx < len(prog.Instructions); idx++ {
		if prog.Instructions[idx].OpCode == asm.Return().OpCode {
			retInsnIdx = idx
			break
		}
	}
	if retInsnIdx == -1 {
		return errors.New("cannot find the return instruction")
	}

	insns, err := compile(filterExpr, spec)
	if err != nil {
		return fmt.Errorf("failed to compile filter expression(%s): %w", filterExpr, err)
	}

	insns[0] = insns[0].WithMetadata(prog.Instructions[injectIdx].Metadata)
	prog.Instructions = append(prog.Instructions[:injectIdx],
		append(insns, prog.Instructions[retInsnIdx+1:]...)...) // replace the original insns with the new ones

	return nil
}

func InjectSkbFilter(spec *btf.Spec, prog *ebpf.ProgramSpec, filterExpr string) error {
	return injectFilter(spec, prog, filterExpr, stubFuncSkb, CompileSkbExpr)
}

func InjectXdpFilter(spec *btf.Spec, prog *ebpf.ProgramSpec, filterExpr string) error {
	return injectFilter(spec, prog, filterExpr, stubFuncXdp, CompileXdpExpr)
}
