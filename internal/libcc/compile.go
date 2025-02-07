// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */
/* Copyright Authors of Cilium */

package libcc

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/pwru/internal/byteorder"
	"rsc.io/c2go/cc"
)

const (
	labelExitFail = "__exit_skb_filter"
	labelReturn   = "__return_skb_filter"
)

var errNotFound = errors.New("not found")

func parse(expr string) (*cc.Expr, error) {
	return cc.ParseExpr(expr)
}

func validateOperator(op cc.ExprOp) error {
	switch op {
	case cc.Eq, cc.EqEq, cc.NotEq, cc.Lt, cc.LtEq, cc.Gt, cc.GtEq:
		return nil
	default:
		return fmt.Errorf("unexpected operator: %s; must be one of =, ==, !=, <, <=, >, >=", op)
	}
}

// validateLeftOperand checks if the left operand is struct member access like:
// [[skb] -> dev] -> ifindex
func validateLeftOperand(left *cc.Expr) error {
	if left == nil {
		return nil
	}

	if left.Left == nil && left.Right == nil {
		return nil
	}

	if left.Op != cc.Dot && left.Op != cc.Arrow {
		return fmt.Errorf("unexpected left operand: %v; must be struct member access", left)
	}

	if left.Right != nil {
		return fmt.Errorf("left operand must be struct member access")
	}

	return validateLeftOperand(left.Left)
}

func parseNumber(right *cc.Expr) (uint64, error) {
	text := right.Text
	if strings.HasPrefix(text, "0x") {
		return strconv.ParseUint(text[2:], 16, 64)
	}
	if strings.HasPrefix(text, "0o") {
		return strconv.ParseUint(text[2:], 8, 64)
	}
	if strings.HasPrefix(text, "0b") {
		return strconv.ParseUint(text[2:], 2, 64)
	}
	return strconv.ParseUint(text, 10, 64)
}

func validateRightOperand(right *cc.Expr) error {
	if right.Op != cc.Number {
		return fmt.Errorf("unexpected right operand: %s; must be a constant number", right)
	}

	if _, err := parseNumber(right); err != nil {
		return fmt.Errorf("right operand is not a number: %w", err)
	}

	return nil
}

// validate checks if the expression is expected simple C expression by
// checking:
// 1. The top level operator is one of the following: =, ==, !=, <, <=, >, >=
// 2. The left operand is struct member access
// 3. The right operand is a constant number in hex, octal, or decimal format
func validate(expr *cc.Expr) error {
	if err := validateOperator(expr.Op); err != nil {
		return err
	}

	if expr.Left == nil {
		return fmt.Errorf("left operand is missing")
	}
	if err := validateLeftOperand(expr.Left); err != nil {
		return err
	}

	if expr.Right == nil {
		return fmt.Errorf("right operand is missing")
	}
	if err := validateRightOperand(expr.Right); err != nil {
		return err
	}

	return nil
}

type astInfo struct {
	offsets   []uint32
	lastField btf.Type
	bigEndian bool // true if the last field is big endian
}

func expr2offset(expr *cc.Expr, ptr *btf.Pointer) (astInfo, error) {
	var ast astInfo

	var exprStack []*cc.Expr
	for left := expr.Left; left != nil; left = left.Left {
		exprStack = append(exprStack, left)
	}

	var offsets []uint32
	offsets = append(offsets, 0)

	seenArrow := false

	var prev btf.Type = ptr
	for i, j := len(exprStack)-2, 0; i >= 0; i-- {
		var (
			prevName string
			member   *btf.Member
			offset   uint32
			err      error
		)

		ptr, useArrow := prev.(*btf.Pointer)
		if useArrow {
			prev = underlyingType(ptr.Target)
		}

		expr := exprStack[i]
		switch v := prev.(type) {
		case *btf.Struct:
			member, err = findStructMember(v, expr.Text)
			prevName = v.Name
		case *btf.Union:
			member, err = findUnionMember(v, expr.Text)
			prevName = v.Name
		default:
			return ast, fmt.Errorf("unexpected type %T of %s(%+v)", v, expr.Text, prev)
		}
		if err != nil {
			return ast, fmt.Errorf("failed to find %s member of %s: %w", expr.Text, prevName, err)
		}

		switch v := prev.(type) {
		case *btf.Struct:
			offset, err = structMemberOffset(v, expr.Text, offset)
		case *btf.Union:
			offset, err = unionMemberOffset(v, expr.Text, offset)
		}
		if err != nil {
			return ast, fmt.Errorf("failed to get offset of %s member of %s: %w", expr.Text, prevName, err)
		}

		prev = underlyingType(member.Type)

		switch expr.Op {
		case cc.Arrow, cc.Dot:
			if !useArrow {
				// access via .
				offsets[j] += offset
			} else {
				// access via ->
				if seenArrow {
					offsets = append(offsets, offset)
					j++
				} else {
					seenArrow = true
					offsets[j] += offset
				}
			}

			if i == 0 {
				ast.offsets = offsets
				ast.lastField = prev
				ast.bigEndian = isBigEndian(member.Type)
				return ast, nil
			}

		default:
			// protected by validateLeftOperand()
			return ast, fmt.Errorf("unexpected operator: %s", expr.Op)
		}
	}

	return ast, fmt.Errorf("unexpected expression: %s", expr)
}

type tgtInfo struct {
	constant  uint64
	typ       btf.Type
	sizof     int
	bigEndian bool
}

func op2insns(insns asm.Instructions, op cc.ExprOp, tgt tgtInfo) asm.Instructions {
	isSigned := false
	intType, isInt := tgt.typ.(*btf.Int)
	if isInt {
		isSigned = intType.Encoding == btf.Signed
	}

	const leftOperandReg = asm.R3

	tgtConst := tgt.constant
	switch tgt.sizof {
	case 1:
		tgtConst = uint64(uint8(tgtConst))

		insns = append(insns,
			asm.And.Imm(leftOperandReg, 0xFF), // r3 &= 0xff
		)
	case 2:
		tgtConst = uint64(uint16(tgtConst))
		if tgt.bigEndian {
			tgtConst = uint64(byteorder.HostToNetwork16(uint16(tgtConst)))
		}

		insns = append(insns,
			asm.And.Imm(leftOperandReg, 0xFFFF), // r3 &= 0xffff
		)
	case 4:
		tgtConst = uint64(uint32(tgtConst))
		if tgt.bigEndian {
			tgtConst = uint64(byteorder.HostToNetwork32(uint32(tgtConst)))
		}

		insns = append(insns,
			asm.LSh.Imm(leftOperandReg, 32), // r3 <<= 32
			asm.RSh.Imm(leftOperandReg, 32), // r3 >>= 32
		)
	}

	var jmpOpCode asm.JumpOp

	switch op {
	case cc.Eq, cc.EqEq:
		// if r3 == tgtConst, goto __return
		jmpOpCode = asm.JEq

	case cc.NotEq:
		// if r3 != tgtConst, goto __return
		jmpOpCode = asm.JNE

	case cc.Lt:
		// if r3 < tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSLT
		} else {
			jmpOpCode = asm.JLT
		}

	case cc.LtEq:
		// if r3 <= tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSLE
		} else {
			jmpOpCode = asm.JLE
		}

	case cc.Gt:
		// if r3 > tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSGT
		} else {
			jmpOpCode = asm.JGT
		}

	case cc.GtEq:
		// if r3 >= tgtConst, goto __return
		if isSigned {
			jmpOpCode = asm.JSGE
		} else {
			jmpOpCode = asm.JGE
		}

	default:
		// protected by validateOperator()
		log.Fatalf("Unexpected operator: %s", op)
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, 1), // r0 = 1
		jmpOpCode.Imm(leftOperandReg, int32(tgtConst), labelReturn),
	)

	return insns
}

func offset2insns(insns asm.Instructions, offsets []uint32) asm.Instructions {
	lastIndex := len(offsets) - 1
	for i := 0; i <= lastIndex; i++ {
		if offsets[i] != 0 {
			insns = append(insns, asm.Add.Imm(asm.R3, int32(offsets[i]))) // r3 += offset
		}
		insns = append(insns,
			asm.Mov.Imm(asm.R2, 8),                      // r2 = 8; always read 8 bytes
			asm.Mov.Reg(asm.R1, asm.R10),                // r1 = r10
			asm.Add.Imm(asm.R1, -8),                     // r1 = r10 - 8
			asm.FnProbeReadKernel.Call(),                // bpf_probe_read_kernel(r1, 8, r3)
			asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord), // r3 = *(r10 - 8)
		)
		if i != lastIndex { // not last member access
			insns = append(insns,
				asm.JEq.Imm(asm.R3, 0, labelExitFail), // if r3 == 0, goto __exit
			)
		}
	}

	return insns
}

// compile compiles the expression into eBPF instructions by compiling
// struct member access into bpf_probe_read_kernel().
//
// compile assumes consuming 8B of stack space for each struct member
// access. It is to bpf_probe_read_kernel() to read the struct member value
// to the stack.
//
// For examples with ATT-like syntax:
//
//  1. skb->dev->ifindex == 1
//     movq r1, r3
//     addq offsetof(skb->dev), r3
//     movq 8, r2
//     movq r10, r1
//     subq 8, r1
//     callq bpf_probe_read_kernel(r1, 8, r3)
//     ldx r10 - 8, r3
//     jeq 0, r3, goto __exit
//     addq offsetof(dev->ifindex), r3
//     movq 8, r2
//     movq r10, r1
//     subq 8, r1
//     callq bpf_probe_read_kernel(r1, 8, r3)
//     ldx r10 - 8, r3
//     movq 1, r0
//     jeq 1, r3, goto __return
//     __exit:
//     movq 0, r0
//     __return:
//     ret
//
//  2. skb->users.refs.counter != 0
//     movq r1, r3
//     addq offsetof(skb->users), r3
//     addq offsetof(users.refs), r3
//     addq offsetof(refs.counter), r3
//     movq 8, r2
//     movq r10, r1
//     subq 8, r1
//     callq bpf_probe_read_kernel(r1, 8, r3)
//     ldx r10 - 8, r3
//     movq 1, r0
//     jne 0, r3, goto __return
//     __exit:
//     movq r4, r0
//     __return:
//     ret
func compile(expr *cc.Expr, ptr *btf.Pointer) (asm.Instructions, error) {
	tgtConst, err := parseNumber(expr.Right)
	if err != nil {
		return nil, fmt.Errorf("failed to parse right operand as number: %w", err)
	}

	ast, err := expr2offset(expr, ptr)
	if err != nil {
		return nil, fmt.Errorf("failed to convert expr to access offsets: %w", err)
	}

	if len(ast.offsets) == 0 {
		return nil, fmt.Errorf("unexpected empty skb/xdp access offsets")
	}

	typofLastField := underlyingType(ast.lastField)
	switch typofLastField.(type) {
	case *btf.Int, *btf.Enum:
	default:
		return nil, fmt.Errorf("unexpected type of last field: %s", typofLastField)
	}

	sizofLastField, err := btf.Sizeof(typofLastField)
	if err != nil {
		return nil, fmt.Errorf("failed to get size of last field type: %w", err)
	}
	switch sizofLastField {
	case 1, 2, 4, 8:
	default:
		return nil, fmt.Errorf("unexpected size %d of last field type %s", sizofLastField, typofLastField)
	}

	// Assume R1 is skb/xdp pointer.
	//
	// Use R1/R2/R3 caller-saved registers directly.

	var insns asm.Instructions
	insns = append(insns,
		asm.Mov.Reg(asm.R3, asm.R1), // r3 = r1; skb/xdp pointer
	)

	insns = offset2insns(insns, ast.offsets)

	tgt := tgtInfo{tgtConst, typofLastField, sizofLastField, ast.bigEndian}
	insns = op2insns(insns, expr.Op, tgt)

	insns = append(insns,
		asm.Mov.Imm(asm.R0, 0).WithSymbol(labelExitFail), // r0 = 0; __exit
		asm.Return().WithSymbol(labelReturn),             // return; __return
	)

	return insns, nil
}

func compileExpr(expr string, ptr *btf.Pointer, pfx string) (asm.Instructions, error) {
	if !strings.HasPrefix(expr, pfx) {
		return nil, fmt.Errorf("skb expr must start with %s prefix", pfx)
	}

	ast, err := parse(expr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expression: %w", err)
	}

	if err := validate(ast); err != nil {
		return nil, fmt.Errorf("failed to validate expression: %w", err)
	}

	return compile(ast, ptr)
}

func CompileSkbExpr(expr string, spec *btf.Spec) (asm.Instructions, error) {
	skb, err := findStruct(spec, "sk_buff")
	if err != nil {
		return nil, fmt.Errorf("failed to find sk_buff struct: %w", err)
	}

	return compileExpr(expr, struct2pointer(skb), "skb")
}

func CompileXdpExpr(expr string, spec *btf.Spec) (asm.Instructions, error) {
	xdp, err := findStruct(spec, "xdp_buff")
	if err != nil {
		return nil, fmt.Errorf("failed to find xdp_buff struct: %w", err)
	}

	return compileExpr(expr, struct2pointer(xdp), "xdp")
}
