// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package shirudo

import (
	"bytes"
	"fmt"
	"maps"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf-sl/signable"
	"github.com/cilium/ebpf/asm"
)

func sortedPrograms(spec *ebpf.CollectionSpec) []*ebpf.ProgramSpec {
	var progs []*ebpf.ProgramSpec
	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		progs = append(progs, spec.Programs[name])
	}
	return progs
}

// mapRefs returns the maps insns references, in the order ebpf-sl puts
// them in the program's fd_array.
func mapRefs(insns asm.Instructions) []string {
	var refs []string
	for _, ins := range insns {
		if ins.IsLoadFromMap() && ins.Reference() != "" && !slices.Contains(refs, ins.Reference()) {
			refs = append(refs, ins.Reference())
		}
	}
	return refs
}

// marshalAsLoader encodes insns as ebpf-sl does into its metadata: maps
// referenced by their index in the program's fd_array, and a direct value
// load, the address of a global variable, as BPF_PSEUDO_MAP_IDX_VALUE at
// its offset.
func marshalAsLoader(insns asm.Instructions) ([]byte, error) {
	insns = slices.Clone(insns)
	refs := mapRefs(insns)
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins
		if !ins.IsLoadFromMap() || ins.Reference() == "" {
			continue
		}
		idx := slices.Index(refs, ins.Reference())
		isValueLoad, offset := ins.Src == asm.PseudoMapValue, uint64(ins.Constant)>>32
		if err := ins.AssociateMapIdx(idx); err != nil {
			return nil, err
		}
		if isValueLoad {
			ins.Src = asm.PseudoMapIdxValue
			ins.Constant = int64(offset<<32 | uint64(uint32(idx)))
		}
	}
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, le); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodedProgram returns the instructions of p where ebpf-sl encoded them
// into its metadata, for a fixup to correct in place.
func encodedProgram(meta []byte, p *ebpf.ProgramSpec) ([]byte, error) {
	encoded, err := marshalAsLoader(p.Instructions)
	if err != nil {
		return nil, fmt.Errorf("program %s: %w", p.Name, err)
	}
	at := bytes.Index(meta, encoded)
	if at < 0 || bytes.Index(meta[at+1:], encoded) >= 0 {
		return nil, fmt.Errorf("program %s: its instructions are not once in the loader's metadata", p.Name)
	}
	return meta[at : at+len(encoded)], nil
}

func isAddrSpaceCast(ins asm.Instruction) bool {
	return ins.OpCode.Class() == asm.ALU64Class && ins.OpCode.ALUOp() == asm.Mov &&
		ins.OpCode.Source() == asm.RegSource && ins.Offset != 0
}

// fixAddrSpaceCasts puts back the offset of every addr_space_cast in the
// programs ebpf-sl encoded into its metadata. The signing branch of
// cilium/ebpf zeroes the offset of a plain Mov when it marshals one, which
// turns the cast into a move the verifier refuses: "BPF_MOV uses reserved
// fields". cilium/ebpf fixed it on main in cc4947e88a91; what is already
// right stays as it is.
func fixAddrSpaceCasts(sl *signable.Loader, spec *ebpf.CollectionSpec) error {
	for _, p := range sortedPrograms(spec) {
		if !slices.ContainsFunc(p.Instructions, isAddrSpaceCast) {
			continue
		}
		encoded, err := encodedProgram(sl.Metadata, p)
		if err != nil {
			return err
		}
		iter := p.Instructions.Iterate()
		for iter.Next() {
			if isAddrSpaceCast(*iter.Ins) {
				le.PutUint16(encoded[int(iter.Offset)*asm.InstructionSize+2:], uint16(iter.Ins.Offset))
			}
		}
	}
	return nil
}
