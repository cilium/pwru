// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */
/* Copyright Authors of Cilium */

package pwru

import (
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Asphaltt/mybtf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/leonhwangprojects/bice"
)

const (
	labelSetSkbMetadataExit = "__set_skb_metadata_exit"
	setSkbMetadataStub      = "set_skb_metadata"

	labelSetXdpMetadataExit = "__set_xdp_metadata_exit"
	setXdpMetadataStub      = "set_xdp_metadata"

	maxSkbMetadata = 4
)

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

func isValidIdentifierChar(c byte) bool {
	return isChar(c) || c == '_' || isDigit(c)
}

func parseMetadataExpr(spec *btf.Spec, expr, meta, buffName, labelExit string) (*SkbMetadata, error) {
	var md SkbMetadata
	md.expr = expr

	if !strings.HasPrefix(expr, meta) {
		return nil, fmt.Errorf("--output-%s-metadata must start with %s", meta, meta)
	}

	for i := len(expr) - 1; i >= 0; i-- {
		if !isValidIdentifierChar(expr[i]) && !slices.Contains([]byte{'.', '-', '>'}, expr[i]) {
			return nil, fmt.Errorf("expr '%s' contains unexpected character '%c'", expr, expr[i])
		}
	}

	for i := len(expr) - 1; i >= 0; i-- {
		if !isValidIdentifierChar(expr[i]) {
			md.last = expr[i+1:]
			break
		}
	}

	types, err := spec.AnyTypesByName(buffName)
	if err != nil {
		return nil, err
	}

	res, err := bice.Access(bice.AccessOptions{
		Expr:      expr,
		Type:      &btf.Pointer{Target: types[0]},
		Src:       asm.R1,
		Dst:       asm.R0,
		LabelExit: labelExit,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse expr '%s': %w", expr, err)
	}

	size, err := btf.Sizeof(res.LastField)
	if err != nil {
		return nil, err
	}
	if size > 8 {
		return nil, fmt.Errorf("%s metadata field '%s' (type %v) is too large, max 8 bytes", meta, md.last, res.LastField)
	}

	md.t = res.LastField
	md.insn = res.Insns
	return &md, nil
}

func parseMetadataExprs(spec *btf.Spec, exprs []string, meta string, buffName, labelExit string) ([]*SkbMetadata, error) {
	var md []*SkbMetadata

	if len(exprs) > maxSkbMetadata {
		return nil, fmt.Errorf("too many %s metadata exprs, max %d", meta, maxSkbMetadata)
	}

	for _, e := range exprs {
		if e == "" {
			continue
		}

		m, err := parseMetadataExpr(spec, e, meta, buffName, labelExit)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s metadata expr '%s': %w", meta, e, err)
		}

		md = append(md, m)
	}

	return md, nil
}

func ParseSkbMetadataExprs(exprs []string, spec *btf.Spec) ([]*SkbMetadata, error) {
	return parseMetadataExprs(spec, exprs, "skb", "sk_buff", labelSetSkbMetadataExit)
}

func ParseXdpMetadataExprs(exprs []string, spec *btf.Spec) ([]*SkbMetadata, error) {
	return parseMetadataExprs(spec, exprs, "xdp", "xdp_buff", labelSetXdpMetadataExit)
}

func injectSetMetadataStub(prog *ebpf.ProgramSpec, md []*SkbMetadata, labelExit, stub string) error {
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
	insns = append(insns, asm.StoreMem(asm.R6, 0, asm.R0, asm.DWord)) // metadata[0] = skb->field

	offset := 0
	for _, m := range md[1:] {
		offset += 8
		insns = append(insns,
			asm.Mov.Reg(asm.R1, asm.R7), // r1 = skb
		)
		insns = append(insns, m.insn...)
		insns = append(insns, asm.StoreMem(asm.R6, int16(offset), asm.R0, asm.DWord)) // metadata[i] = skb->field
	}

	insns = append(insns,
		asm.Return().WithSymbol(labelExit),
	)

	return injectBpfStub(prog, stub, insns)
}

func InjectSetSkbMetadata(prog *ebpf.ProgramSpec, md []*SkbMetadata) error {
	return injectSetMetadataStub(prog, md, labelSetSkbMetadataExit, setSkbMetadataStub)
}

func InjectSetXdpMetadata(prog *ebpf.ProgramSpec, md []*SkbMetadata) error {
	return injectSetMetadataStub(prog, md, labelSetXdpMetadataExit, setXdpMetadataStub)
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
