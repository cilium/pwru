// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package shirudo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf-sl/signable"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/sys"
	"golang.org/x/sys/unix"
)

// A shirudo target runs the loader with the context libbpf's gen_loader
// defines in skel_internal.h: struct bpf_loader_ctx, then a struct
// bpf_map_desc per map and a struct bpf_prog_desc per program, where the
// loader leaves the descriptors it made.
const (
	ctxLogLevel  = 8
	ctxLogSize   = 12
	ctxLogBuf    = 16
	ctxSize      = 24
	mapDescSize  = 16
	progDescSize = 4
)

// The context of the loader ebpf-sl generates, which the shim keeps in
// the loader's data.
var (
	slFDs         = int16(unsafe.Offsetof(signable.LoaderContext{}.FDs))
	slProgLogs    = int16(unsafe.Offsetof(signable.LoaderContext{}.ProgLogs))
	slProgLogSize = int16(unsafe.Sizeof(signable.ProgramLog{}))
	slLogBuf      = int16(unsafe.Offsetof(signable.ProgramLog{}.LogBuf))
	slLogLevel    = int16(unsafe.Offsetof(signable.ProgramLog{}.LogLevel))
	slLogSize     = int16(unsafe.Offsetof(signable.ProgramLog{}.LogSize))
	slCtxSize     = int(unsafe.Sizeof(signable.LoaderContext{}))
	slMaxProgs    = len(signable.LoaderContext{}.ProgLogs)
)

const (
	dataMapIdx    = 0 // the loader's data map, fd_array[0]
	mapElemAttrSz = 32
	freezeAttrSz  = 4
)

// The shim keeps shirudo's context in R6 and ebpf-sl's in R7; both are
// preserved across helper and BPF-to-BPF calls.
const (
	rCtx   = asm.R6
	rSlCtx = asm.R7
	rFD    = asm.R8
	rErr   = asm.R9
)

// shimData lays out, behind ebpf-sl's metadata in the loader's data,
// what the shim reads and writes: ebpf-sl's context, and the attributes,
// key and value of each preload.
type shimData struct {
	data   []byte
	ctxOff uint32
}

func (d *shimData) add(b []byte) uint32 {
	d.data = pad8(d.data)
	off := uint32(len(d.data))
	d.data = append(d.data, b...)
	return off
}

// shim is the program that runs before ebpf-sl's loader, and the slots
// of ebpf-sl's context it maps shirudo's descriptors to.
type shim struct {
	d         shimData
	insns     asm.Instructions
	mapSlots  []int
	progSlots []int
	nrSlots   int
}

func (s *shim) emit(insns ...asm.Instruction) {
	s.insns = append(s.insns, insns...)
}

func (s *shim) slotOff(slot int) int16 {
	return slFDs + int16(slot*4)
}

func (s *shim) sysBpf(cmd sys.Cmd, attrOff uint32, attrSize int32) {
	s.emit(
		asm.Mov.Imm(asm.R1, int32(cmd)),
		asm.LoadMapValueIdx(asm.R2, dataMapIdx, attrOff),
		asm.Mov.Imm(asm.R3, attrSize),
		asm.FnSysBpf.Call(),
		asm.JSLT.Imm(asm.R0, 0, "shim_fail"),
	)
}

// passLogs hands every program load the verifier log shirudo gave the
// loader; it keeps the log of the load that failed.
func (s *shim) passLogs(nrProgs int) {
	s.emit(
		asm.LoadMem(asm.R1, rCtx, ctxLogLevel, asm.Word),
		asm.LoadMem(asm.R2, rCtx, ctxLogSize, asm.Word),
		asm.LoadMem(asm.R3, rCtx, ctxLogBuf, asm.DWord),
	)
	for i := range nrProgs {
		off := slProgLogs + int16(i)*slProgLogSize
		s.emit(
			asm.StoreMem(rSlCtx, off+slLogBuf, asm.R3, asm.DWord),
			asm.StoreMem(rSlCtx, off+slLogLevel, asm.R1, asm.Word),
			asm.StoreMem(rSlCtx, off+slLogSize, asm.R2, asm.Word),
		)
	}
}

// createPreload creates, fills and, for .rodata, freezes a global data
// map, and leaves its descriptor in its slot, where ebpf-sl finds it and
// creates no other.
func (s *shim) createPreload(p preload, slot int) error {
	attr := sys.MapCreateAttrRaw{
		MapType:    uint32(p.spec.Type),
		KeySize:    p.spec.KeySize,
		ValueSize:  p.spec.ValueSize,
		MaxEntries: p.spec.MaxEntries,
		MapFlags:   p.spec.Flags,
		MapName:    sys.NewObjName(p.name),
		MapExtra:   p.spec.MapExtra,
	}
	createAttr, err := binary.Append(nil, le, attr)
	if err != nil {
		return fmt.Errorf("map %s: %w", p.name, err)
	}
	createOff := s.d.add(createAttr)
	updateOff := s.d.add(make([]byte, mapElemAttrSz))
	keyOff := s.d.add(make([]byte, 4))
	valueOff := s.d.add(p.value)

	s.sysBpf(sys.BPF_MAP_CREATE, createOff, int32(len(createAttr)))
	s.emit(
		asm.StoreMem(rSlCtx, s.slotOff(slot), asm.R0, asm.Word),
		asm.Mov.Reg(rFD, asm.R0),
		asm.LoadMapValueIdx(asm.R2, dataMapIdx, updateOff),
		asm.StoreMem(asm.R2, 0, rFD, asm.Word),
		asm.LoadMapValueIdx(asm.R1, dataMapIdx, keyOff),
		asm.StoreMem(asm.R2, 8, asm.R1, asm.DWord),
		asm.LoadMapValueIdx(asm.R1, dataMapIdx, valueOff),
		asm.StoreMem(asm.R2, 16, asm.R1, asm.DWord),
	)
	s.sysBpf(sys.BPF_MAP_UPDATE_ELEM, updateOff, mapElemAttrSz)
	if !p.freeze {
		return nil
	}
	freezeOff := s.d.add(make([]byte, freezeAttrSz))
	s.emit(
		asm.LoadMapValueIdx(asm.R2, dataMapIdx, freezeOff),
		asm.StoreMem(asm.R2, 0, rFD, asm.Word),
	)
	s.sysBpf(sys.BPF_MAP_FREEZE, freezeOff, freezeAttrSz)
	return nil
}

// copyOut hands shirudo the descriptors, in its order of maps and
// programs.
func (s *shim) copyOut() {
	for i, slot := range s.mapSlots {
		s.emit(
			asm.LoadMem(asm.R1, rSlCtx, s.slotOff(slot), asm.Word),
			asm.StoreMem(rCtx, int16(ctxSize+i*mapDescSize), asm.R1, asm.Word),
		)
	}
	progDescOff := ctxSize + len(s.mapSlots)*mapDescSize
	for i, slot := range s.progSlots {
		s.emit(
			asm.LoadMem(asm.R1, rSlCtx, s.slotOff(slot), asm.Word),
			asm.StoreMem(rCtx, int16(progDescOff+i*progDescSize), asm.R1, asm.Word),
		)
	}
}

// failure returns the error ebpf-sl left in a slot, or EINVAL when it
// failed without one, as on a BTF load, after closing every descriptor
// made: shirudo expects a failed loader to leave none.
func (s *shim) failure() {
	for slot := range s.nrSlots {
		next := fmt.Sprintf("shim_err_%d", slot)
		s.emit(
			asm.LoadMemSX(asm.R1, rSlCtx, s.slotOff(slot), asm.Word),
			asm.JSGE.Imm(asm.R1, 0, next),
			asm.Mov.Reg(asm.R0, asm.R1),
			asm.Ja.Label("shim_fail"),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(next),
		)
	}
	s.emit(asm.Mov.Imm(asm.R0, -int32(unix.EINVAL)))

	s.emit(asm.Mov.Reg(rErr, asm.R0).WithSymbol("shim_fail"))
	for slot := range s.nrSlots {
		next := fmt.Sprintf("shim_close_%d", slot)
		s.emit(
			asm.LoadMemSX(asm.R1, rSlCtx, s.slotOff(slot), asm.Word),
			asm.JSLE.Imm(asm.R1, 0, next),
			asm.FnSysClose.Call(),
			asm.Mov.Imm(asm.R0, 0).WithSymbol(next),
		)
	}
	s.emit(
		asm.Mov.Reg(asm.R0, rErr),
		asm.Return(),
	)
}

// buildShim lays out the shim's data behind meta, ebpf-sl's metadata,
// and returns the loader: the shim, then ebpf-sl's loader, which the
// shim calls with its context.
func buildShim(sl *signable.Loader, pre []preload, mapSlots, progSlots []int) ([]byte, []byte, error) {
	if len(progSlots) > slMaxProgs {
		return nil, nil, fmt.Errorf("%d programs, ebpf-sl loads at most %d", len(progSlots), slMaxProgs)
	}
	s := &shim{
		d:         shimData{data: bytes.Clone(sl.Metadata)},
		mapSlots:  mapSlots,
		progSlots: progSlots,
		nrSlots:   len(sl.FDSlots),
	}
	s.d.ctxOff = s.d.add(make([]byte, slCtxSize))

	s.emit(
		asm.Mov.Reg(rCtx, asm.R1),
		asm.LoadMapValueIdx(rSlCtx, dataMapIdx, s.d.ctxOff),
	)
	s.passLogs(len(progSlots))
	for _, p := range pre {
		slot := -1
		for i, fs := range sl.FDSlots {
			if fs.Map != nil && *fs.Map == p.name {
				slot = i
			}
		}
		if slot < 0 {
			return nil, nil, fmt.Errorf("map %s has no slot in the loader", p.name)
		}
		if err := s.createPreload(p, slot); err != nil {
			return nil, nil, err
		}
	}

	s.emit(asm.Mov.Reg(asm.R1, rSlCtx))
	callIdx := len(s.insns)
	s.emit(
		asm.Instruction{OpCode: asm.OpCode(asm.JumpClass).SetJumpOp(asm.Call), Src: asm.PseudoCall},
		asm.JNE.Imm(asm.R0, 0, "shim_error"),
	)
	s.copyOut()
	s.emit(
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)
	s.emit(asm.Mov.Imm(asm.R0, 0).WithSymbol("shim_error"))
	s.failure()

	// ebpf-sl's loader follows the shim: the call's offset is from the
	// instruction after it to the end of the shim.
	var callOff, total int64
	for i, ins := range s.insns {
		if i == callIdx {
			callOff = total
		}
		total += int64(ins.Size() / asm.InstructionSize)
	}
	s.insns[callIdx].Constant = total - callOff - 1

	var buf bytes.Buffer
	if err := s.insns.Marshal(&buf, le); err != nil {
		return nil, nil, fmt.Errorf("shim: %w", err)
	}
	return append(buf.Bytes(), sl.Insns...), s.d.data, nil
}
