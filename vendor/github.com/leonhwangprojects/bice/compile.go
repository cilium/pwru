// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"fmt"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"rsc.io/c2go/cc"
)

const (
	labelExitFail = "__exit_bice_filter"
	labelReturn   = "__return_bice_filter"
)

// IsMemberBitfield reports whether the member is a bitfield attribute.
func IsMemberBitfield(member *btf.Member) bool {
	return member != nil && member.BitfieldSize != 0
}

type rightInfo struct {
	constant uint64
	enum     string
}

func parseRightOperand(right *cc.Expr) (rightInfo, error) {
	var ri rightInfo

	switch right.Op {
	case cc.Name:
		ri.enum = right.Text

	case cc.Number:
		constant, err := parseNumber(right.Text)
		if err != nil {
			return ri, fmt.Errorf("failed to parse number %s: %w", right.Text, err)
		}

		ri.constant = constant
	default:
		return ri, fmt.Errorf("unexpected right operand: %v", right)
	}

	return ri, nil
}

func (ri *rightInfo) enum2const(t btf.Type) error {
	if ri.enum == "" {
		return nil
	}

	enum, ok := t.(*btf.Enum)
	if !ok {
		return fmt.Errorf("unexpected type %T for %s", t, ri.enum)
	}

	for i, value := range enum.Values {
		if value.Name == ri.enum {
			ri.constant = uint64(i)
			return nil
		}
	}

	return fmt.Errorf("%s not found in enum %s", ri.enum, enum.Name)
}

type astInfo struct {
	offsets   []uint32
	member    *btf.Member
	lastField btf.Type
	bigEndian bool // true if the last field is big endian
}

func expr2offset(expr *cc.Expr, typ btf.Type) (astInfo, error) {
	var ast astInfo

	var exprStack []*cc.Expr
	for left := expr; left != nil; left = left.Left {
		exprStack = append(exprStack, left)
	}

	if len(exprStack) == 1 {
		ast.lastField = typ
		ast.bigEndian = mybtf.IsBigEndian(typ)
		return ast, nil
	}

	var offsets []uint32

	prev := mybtf.UnderlyingType(typ)
	for i, j := len(exprStack)-2, -1; i >= 0; i-- {
		var (
			prevName string
			member   *btf.Member
			offset   uint32
			err      error
		)

		ptr, useArrow := prev.(*btf.Pointer)
		if useArrow {
			prev = mybtf.UnderlyingType(ptr.Target)
		}

		expr := exprStack[i]
		switch v := prev.(type) {
		case *btf.Struct:
			member, err = mybtf.FindStructMember(v, expr.Text)
			prevName = v.Name
		case *btf.Union:
			member, err = mybtf.FindUnionMember(v, expr.Text)
			prevName = v.Name
		default:
			return ast, fmt.Errorf("unexpected type %T of %s(%+v)", v, expr.Text, prev)
		}
		if err != nil {
			return ast, fmt.Errorf("failed to find member %s of %s: %w", expr.Text, prevName, err)
		}

		switch v := prev.(type) {
		case *btf.Struct:
			offset, err = mybtf.StructMemberOffset(v, expr.Text)
		case *btf.Union:
			offset, err = mybtf.UnionMemberOffset(v, expr.Text)
		}
		if err != nil {
			return ast, fmt.Errorf("failed to get offset of member %s of %s: %w", expr.Text, prevName, err)
		}

		prev = mybtf.UnderlyingType(member.Type)

		switch expr.Op {
		case cc.Arrow, cc.Dot:
			if !useArrow {
				// access via .
				if j >= 0 {
					offsets[j] += offset
				} else {
					return ast, fmt.Errorf("unexpected access via .: %s", expr)
				}
			} else {
				// access via ->
				offsets = append(offsets, offset)
				j++
			}

			if IsMemberBitfield(member) {
				offsets[j] = member.Offset.Bytes()
			}

			if i == 0 {
				ast.offsets = offsets
				ast.member = member
				ast.lastField = member.Type
				ast.bigEndian = mybtf.IsBigEndian(member.Type)
				return ast, nil
			}

		default:
			// protected by validateLeftOperand()
			return ast, fmt.Errorf("unexpected operator: %s", expr.Op)
		}
	}

	return ast, fmt.Errorf("unexpected expression: %s", expr)
}

func offset2insns(insns asm.Instructions, offsets []uint32, dst asm.Register, labelExit string, dontReadLastField bool) (asm.Instructions, bool) {
	labelUsed := false
	lastIndex := len(offsets) - 1
	for i := 0; i <= lastIndex; i++ {
		if offsets[i] != 0 {
			insns = append(insns, asm.Add.Imm(asm.R3, int32(offsets[i]))) // r3 += offset
		}
		if i == lastIndex && dontReadLastField {
			if dst != asm.R3 {
				insns = append(insns, asm.Mov.Reg(dst, asm.R3))
			}
			break
		}
		insns = append(insns,
			asm.Mov.Imm(asm.R2, 8),       // r2 = 8; always read 8 bytes
			asm.Mov.Reg(asm.R1, asm.R10), // r1 = r10
			asm.Add.Imm(asm.R1, -8),      // r1 = r10 - 8
			asm.FnProbeReadKernel.Call(), // bpf_probe_read_kernel(r1, 8, r3)
		)
		if i != lastIndex { // not last member access
			labelUsed = true
			insns = append(insns,
				asm.LoadMem(asm.R3, asm.R10, -8, asm.DWord), // r3 = *(r10 - 8)
				asm.JEq.Imm(asm.R3, 0, labelExit),           // if r3 == 0, goto __exit
			)
		} else {
			insns = append(insns,
				asm.LoadMem(dst, asm.R10, -8, asm.DWord),
			)
		}
	}

	return insns, labelUsed
}

func bitfield2insns(insns asm.Instructions, constant uint64, member *btf.Member, reg asm.Register) (asm.Instructions, uint64) {
	delta := member.Offset & 0x7
	if delta != 0 {
		insns = append(insns,
			asm.RSh.Imm(reg, int32(delta)), // reg >>= delta
		)
	}

	mask := (uint64(1) << uint64(member.BitfieldSize)) - 1
	constant &= mask
	insns = append(insns,
		asm.And.Imm(reg, int32(mask)), // reg &= mask
	)

	return insns, constant
}

type tgtInfo struct {
	constant  uint64
	typ       btf.Type
	sizof     int
	bigEndian bool
}

func tgt2insns(insns asm.Instructions, tgt tgtInfo, reg asm.Register) (asm.Instructions, uint64) {
	tgtConst := tgt.constant
	switch tgt.sizof {
	case 1:
		tgtConst = uint64(uint8(tgtConst))

		insns = append(insns,
			asm.And.Imm(reg, 0xFF), // reg &= 0xff
		)
	case 2:
		tgtConst = uint64(uint16(tgtConst))
		if tgt.bigEndian {
			tgtConst = uint64(h2ns(uint16(tgtConst)))
		}

		insns = append(insns,
			asm.And.Imm(reg, 0xFFFF), // reg &= 0xffff
		)
	case 4:
		tgtConst = uint64(uint32(tgtConst))
		if tgt.bigEndian {
			tgtConst = uint64(h2nl(uint32(tgtConst)))
		}

		insns = append(insns,
			asm.LSh.Imm(reg, 32), // reg <<= 32
			asm.RSh.Imm(reg, 32), // reg >>= 32
		)

	case 8:
		if tgt.bigEndian {
			tgtConst = h2nll(tgtConst)
		}
	}

	return insns, tgtConst
}

func op2insns(insns asm.Instructions, op cc.ExprOp, tgt tgtInfo) (asm.Instructions, error) {
	isSigned := false
	intType, isInt := tgt.typ.(*btf.Int)
	if isInt {
		isSigned = intType.Encoding == btf.Signed
	}

	const leftOperandReg = asm.R3

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
		return nil, fmt.Errorf("unexpected operator: %s; must be one of =, ==, !=, <, <=, >, >=", op)
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, 1), // r0 = 1
		jmpOpCode.Imm(leftOperandReg, int32(tgt.constant), labelReturn),
	)

	return insns, nil
}

func checkLastField(member *btf.Member, t btf.Type) (int, error) {
	if IsMemberBitfield(member) {
		bits := (member.Offset & 0x7) + member.BitfieldSize
		if bits > 64 {
			return 0, fmt.Errorf("unsupported too large bitfield named '%s'", member.Name)
		}

		return 0, nil
	}

	t = mybtf.UnderlyingType(t)
	switch t.(type) {
	case *btf.Int, *btf.Enum, *btf.Pointer:
		return btf.Sizeof(t)

	default:
		return 0, fmt.Errorf("unexpected type of last field: %s", t)
	}
}

func compile(expr *cc.Expr, typ btf.Type) (asm.Instructions, error) {
	if expr == nil || expr.Right == nil {
		return nil, fmt.Errorf("expression or right operand is nil")
	}

	ri, err := parseRightOperand(expr.Right)
	if err != nil {
		return nil, fmt.Errorf("failed to parse right operand: %w", err)
	}

	ast, err := expr2offset(expr.Left, typ)
	if err != nil {
		return nil, fmt.Errorf("failed to convert expr to access offsets: %w", err)
	}

	err = ri.enum2const(ast.lastField)
	if err != nil {
		return nil, fmt.Errorf("failed to convert enum to constant: %w", err)
	}

	sizofLastField, err := checkLastField(ast.member, ast.lastField)
	if err != nil {
		return nil, err
	}

	// Use R1/R2/R3 caller-saved registers directly.

	var insns asm.Instructions
	insns = append(insns,
		asm.Mov.Reg(asm.R3, asm.R1), // r3 = r1
	)

	insns, labelUsed := offset2insns(insns, ast.offsets, asm.R3, labelExitFail, false)

	tgt := tgtInfo{ri.constant, ast.lastField, sizofLastField, ast.bigEndian}
	if IsMemberBitfield(ast.member) {
		insns, tgt.constant = bitfield2insns(insns, tgt.constant, ast.member, asm.R3)
	} else {
		insns, tgt.constant = tgt2insns(insns, tgt, asm.R3)
	}

	insns, err = op2insns(insns, expr.Op, tgt)
	if err != nil {
		return nil, fmt.Errorf("failed to convert operator to instructions: %w", err)
	}

	xorR0 := asm.Xor.Reg(asm.R0, asm.R0)
	if labelUsed {
		xorR0 = xorR0.WithSymbol(labelExitFail)
	}
	insns = append(insns,
		xorR0,                                // r0 = 0
		asm.Return().WithSymbol(labelReturn), // return; __return
	)

	return insns, nil
}
