// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

type AccessOptions struct {
	Insns     asm.Instructions
	Expr      string
	Type      btf.Type
	Src       asm.Register
	Dst       asm.Register
	LabelExit string
}

type AccessResult struct {
	Insns     asm.Instructions
	LastField btf.Type
	LabelUsed bool
}

func Access(opts AccessOptions) (AccessResult, error) {
	if opts.Expr == "" || opts.Type == nil || opts.LabelExit == "" {
		return AccessResult{}, fmt.Errorf("invalid options")
	}

	ast, err := parse(opts.Expr)
	if err != nil {
		return AccessResult{}, fmt.Errorf("failed to compile expression %s: %w", opts.Expr, err)
	}

	err = validateLeftOperand(ast)
	if err != nil {
		return AccessResult{}, fmt.Errorf("expression is not struct/union member access: %w", err)
	}

	offsets, err := expr2offset(ast, opts.Type)
	if err != nil {
		return AccessResult{}, fmt.Errorf("failed to convert expression to offsets: %w", err)
	}

	if len(offsets.offsets) == 0 {
		return AccessResult{}, fmt.Errorf("expr should be struct/union member access")
	}

	var size int
	isStr := mybtf.IsConstCharPtr(offsets.lastField)
	isArr := mybtf.IsCharArray(offsets.lastField)
	if isStr || isArr {
		size = 8
	} else {
		size, err = checkLastField(offsets.member, offsets.lastField)
		if err != nil {
			return AccessResult{}, err
		}
	}

	insns := opts.Insns
	if opts.Src != asm.R3 {
		insns = append(insns, asm.Mov.Reg(asm.R3, opts.Src))
	}
	insns, labelUsed := offset2insns(insns, offsets.offsets, opts.Dst, opts.LabelExit, isArr)

	tgt := tgtInfo{0, offsets.lastField, size, offsets.bigEndian}
	if IsMemberBitfield(offsets.member) {
		insns, _ = bitfield2insns(insns, tgt.constant, offsets.member, opts.Dst)
	} else {
		insns, _ = tgt2insns(insns, tgt, opts.Dst)
	}

	return AccessResult{
		Insns:     insns,
		LastField: offsets.lastField,
		LabelUsed: labelUsed,
	}, nil
}
