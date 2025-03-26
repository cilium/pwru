// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */
/* Copyright Authors of Cilium */

package pwru

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/leonhwangprojects/bice"
)

const labelSetSkbMetadataExit = "__set_skb_metadata_exit"

const setSkbMetadataStub = "set_skb_metadata"

const maxSkbMetadata = 4

type SkbMetadata struct {
	expr string
	last string
	t    btf.Type // type of last field
	insn asm.Instructions
}

func isChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isValidChar(c byte) bool {
	return isChar(c) || c == '_' || isDigit(c)
}

func newSkbMetadata(expr string, spec *btf.Spec) (*SkbMetadata, error) {
	var md SkbMetadata
	md.expr = expr

	if !strings.HasPrefix(expr, "skb") {
		return nil, errors.New("--output-skb-metadata must starts with skb")
	}

	for i := len(expr) - 1; i >= 0; i-- {
		if !isValidChar(expr[i]) {
			md.last = expr[i+1:]
			break
		}
	}

	types, err := spec.AnyTypesByName("sk_buff")
	if err != nil {
		return nil, err
	}

	skb := types[0]
	ptr := &btf.Pointer{Target: skb}

	res, err := bice.Access(bice.AccessOptions{
		Expr:      expr,
		Type:      ptr,
		Src:       asm.R1,
		Dst:       asm.R3,
		LabelExit: labelSetSkbMetadataExit,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse expr %s: %w", expr, err)
	}

	size, err := btf.Sizeof(res.LastField)
	if err != nil {
		return nil, err
	}
	if size > 8 {
		return nil, fmt.Errorf("skb metadata field '%s' (type %v) is too large, max 8 bytes", md.last, res.LastField)
	}

	md.t = res.LastField
	md.insn = res.Insns
	return &md, nil
}

func ParseSkbMetadataExprs(exprs []string, spec *btf.Spec) ([]*SkbMetadata, error) {
	var md []*SkbMetadata

	for _, e := range exprs {
		if e == "" {
			continue
		}

		m, err := newSkbMetadata(e, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to parse skb metadata expr %s: %w", e, err)
		}

		md = append(md, m)
	}

	if len(md) > maxSkbMetadata {
		return nil, fmt.Errorf("too many skb metadata exprs, max %d", maxSkbMetadata)
	}

	return md, nil
}

func InjectSetSkbMetadata(prog *ebpf.ProgramSpec, md []*SkbMetadata) error {
	if len(md) == 0 {
		return nil
	}

	var insns asm.Instructions
	if len(md) > 1 {
		insns = append(insns,
			asm.Mov.Reg(asm.R7, asm.R1), // r7 = skb
		)
	}
	insns = append(insns,
		asm.Mov.Reg(asm.R6, asm.R2), // r6 = metadata
	)

	insns = append(insns, md[0].insn...)
	insns = append(insns, asm.StoreMem(asm.R6, 0, asm.R3, asm.DWord)) // metadata[0] = skb->field

	offset := 0
	for _, m := range md[1:] {
		offset += 8
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R7), // r1 = skb
		)
		insns = append(insns, m.insn...)
		insns = append(insns, asm.StoreMem(asm.R6, int16(offset), asm.R3, asm.DWord)) // metadata[i] = skb->field
	}

	insns = append(insns,
		asm.Return().WithSymbol(labelSetSkbMetadataExit),
	)

	startIdx := -1
	for i, ins := range prog.Instructions {
		if ins.Symbol() == setSkbMetadataStub {
			startIdx = i
			break
		}
	}
	if startIdx == -1 {
		return errors.New("failed to find set_skb_metadata stub")
	}

	retIdx := -1
	retOpCode := asm.Return().OpCode
	for i := startIdx + 1; i < len(prog.Instructions); i++ {
		if prog.Instructions[i].OpCode == retOpCode {
			retIdx = i
			break
		}
	}
	if retIdx == -1 {
		return errors.New("failed to find ret instruction")
	}

	// replace the stub's instructions
	insns[0] = insns[0].WithMetadata(prog.Instructions[startIdx].Metadata)
	prog.Instructions = append(prog.Instructions[:startIdx],
		append(insns, prog.Instructions[retIdx+1:]...)...)

	return nil
}

func outputSkbMetadata(w io.Writer, md []*SkbMetadata, data []uint64) {
	for i, m := range md {
		var b [8]byte
		binary.NativeEndian.PutUint64(b[:], data[i])

		s, err := mybtf.DumpData(m.t, b[:])
		if err != nil {
			fmt.Fprintf(w, " %s=..ERR..", m.last)
		} else {
			fmt.Fprintf(w, " %s=%s", m.last, s)
		}
	}
}
