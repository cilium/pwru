package cbpfc

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf/asm"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

// internal label when packet doesn't match
const noMatchLabel = "nomatch"

// alu operation to eBPF
var aluToEBPF = map[bpf.ALUOp]asm.ALUOp{
	bpf.ALUOpAdd:        asm.Add,
	bpf.ALUOpSub:        asm.Sub,
	bpf.ALUOpMul:        asm.Mul,
	bpf.ALUOpDiv:        asm.Div,
	bpf.ALUOpOr:         asm.Or,
	bpf.ALUOpAnd:        asm.And,
	bpf.ALUOpShiftLeft:  asm.LSh,
	bpf.ALUOpShiftRight: asm.RSh,
	bpf.ALUOpMod:        asm.Mod,
	bpf.ALUOpXor:        asm.Xor,
}

// bpf sizes to ebpf
var sizeToEBPF = map[int]asm.Size{
	1: asm.Byte,
	2: asm.Half,
	4: asm.Word,
}

// EBPFOpts control how a cBPF filter is converted to eBPF
type EBPFOpts struct {
	// PacketStart is a register holding a pointer to the start of the packet.
	// Not modified.
	PacketStart asm.Register
	// PacketEnd is a register holding a pointer to the end of the packet.
	// Not modified.
	PacketEnd asm.Register
	// Register to output the filter return value in.
	Result asm.Register

	// Label to jump to with the result of the filter in register Result.
	ResultLabel string

	// Working are registers used internally.
	// Caller saved.
	// Must be different to PacketStart and PacketEnd, but Result can be reused.
	Working [4]asm.Register

	// StackOffset is the number of bytes of stack already used / reserved.
	// R10 (ebpf frame pointer) + StackOffset will be used as the top of the stack.
	StackOffset int

	// LabelPrefix is the prefix to prepend to labels used internally.
	LabelPrefix string
}

// ebpfOpts is the internal version of EBPFOpts
type ebpfOpts struct {
	EBPFOpts

	// Registers mapping directly to cBPF
	regA asm.Register
	regX asm.Register

	// Temp / scratch register
	regTmp asm.Register

	// Register for indirect packet loads
	// Allows the range of a packet guard to be preserved across multiple loads by the verifier
	regIndirect asm.Register
}

func (e ebpfOpts) reg(reg bpf.Register) asm.Register {
	switch reg {
	case bpf.RegA:
		return e.regA
	case bpf.RegX:
		return e.regX
	default:
		panic("unknown bpf register")
	}
}

func (e ebpfOpts) label(name string) string {
	return fmt.Sprintf("%s_%s", e.LabelPrefix, name)
}

// eBPF stack address offset for BPF scratch slot scracth.
func (e ebpfOpts) stackOffset(scratch int) int16 {
	// First usable stack space ends at StackOffset.
	return -int16(e.StackOffset + (scratch+1)*4)
}

// ToEBF converts a cBPF filter to eBPF.
//
// The generated eBPF code always jumps to opts.ResultLabel, with register opts.Result containing the filter's return value:
// 0 if the packet does not match the cBPF filter,
// non 0 if the packet does match.
func ToEBPF(filter []bpf.Instruction, opts EBPFOpts) (asm.Instructions, error) {
	blocks, err := compile(filter)
	if err != nil {
		return nil, err
	}

	eOpts := ebpfOpts{
		EBPFOpts:    opts,
		regA:        opts.Working[0],
		regX:        opts.Working[1],
		regTmp:      opts.Working[2],
		regIndirect: opts.Working[3],
	}

	// opts.Result does not have to be unique
	err = registersUnique(eOpts.PacketStart, eOpts.PacketEnd, eOpts.regA, eOpts.regX, eOpts.regTmp, eOpts.regIndirect)
	if err != nil {
		return nil, err
	}

	err = registerValid(eOpts.Result)
	if err != nil {
		return nil, err
	}

	if eOpts.StackOffset&1 == 1 {
		return nil, errors.Errorf("unaligned stack offset")
	}

	eInsns := asm.Instructions{}

	for _, block := range blocks {
		for i, insn := range block.insns {
			eInsn, err := insnToEBPF(insn, block, eOpts)
			if err != nil {
				return nil, errors.Wrapf(err, "unable to compile %v", insn)
			}

			// First insn of the block, add symbol so it can be referenced in jumps
			if i == 0 {
				eInsn[0] = eInsn[0].WithSymbol(eOpts.label(block.Label()))
			}

			eInsns = append(eInsns, eInsn...)
		}
	}

	// kernel verifier does not like dead code - only include no match block if we used it
	if _, ok := eInsns.ReferenceOffsets()[eOpts.label(noMatchLabel)]; ok {
		eInsns = append(eInsns,
			asm.Mov.Imm(eOpts.Result, 0).WithSymbol(eOpts.label(noMatchLabel)),
			asm.Ja.Label(opts.ResultLabel),
		)
	}

	return eInsns, nil
}

// registersUnique ensures the registers are valid and unique
func registersUnique(regs ...asm.Register) error {
	seen := make(map[asm.Register]struct{}, len(regs))

	for _, reg := range regs {
		if err := registerValid(reg); err != nil {
			return err
		}

		if _, ok := seen[reg]; ok {
			return errors.Errorf("register %v used twice", reg)
		}
		seen[reg] = struct{}{}
	}

	return nil
}

// registerValid ensures that a register is a valid ebpf register
func registerValid(reg asm.Register) error {
	if reg > asm.R9 {
		return errors.Errorf("invalid register %v", reg)
	}

	return nil
}

// insnToEBPF compiles an instruction to a set of eBPF instructions
func insnToEBPF(insn instruction, blk *block, opts ebpfOpts) (asm.Instructions, error) {
	switch i := insn.Instruction.(type) {

	case bpf.LoadConstant:
		return ebpfInsn(asm.Mov.Imm32(opts.reg(i.Dst), int32(i.Val)))
	case bpf.LoadScratch:
		return ebpfInsn(asm.LoadMem(opts.reg(i.Dst), asm.R10, opts.stackOffset(i.N), asm.Word))

	case bpf.LoadAbsolute:
		return packetLoad(opts, opts.PacketStart, i.Off, i.Size, func(src asm.Register, offset int16, size asm.Size) asm.Instructions {
			return appendNtoh(opts.regA, size,
				asm.LoadMem(opts.regA, src, offset, size),
			)
		})

	case bpf.LoadIndirect:
		// last packet guard set opts.regIndirect to packetstart + x
		return packetLoad(opts, opts.regIndirect, i.Off, i.Size, func(src asm.Register, offset int16, size asm.Size) asm.Instructions {
			return appendNtoh(opts.regA, size,
				asm.LoadMem(opts.regA, src, offset, size),
			)
		})

	case bpf.LoadMemShift:
		return packetLoad(opts, opts.PacketStart, i.Off, 1, func(src asm.Register, offset int16, size asm.Size) asm.Instructions {
			return []asm.Instruction{
				asm.LoadMem(opts.regX, src, offset, size),
				asm.And.Imm32(opts.regX, 0xF), // clear upper 4 bits
				asm.LSh.Imm32(opts.regX, 2),   // 32bit words to bytes
			}
		})

	case bpf.StoreScratch:
		return ebpfInsn(asm.StoreMem(asm.R10, opts.stackOffset(i.N), opts.reg(i.Src), asm.Word))

	case bpf.LoadExtension:
		if i.Num != bpf.ExtLen {
			return nil, errors.Errorf("unsupported BPF extension %v", i)
		}

		return ebpfInsn(
			asm.Mov.Reg(opts.regA, opts.PacketEnd),
			asm.Sub.Reg32(opts.regA, opts.PacketStart),
		)

	case bpf.ALUOpConstant:
		return ebpfInsn(aluToEBPF[i.Op].Imm32(opts.regA, int32(i.Val)))
	case bpf.ALUOpX:
		return ebpfInsn(aluToEBPF[i.Op].Reg32(opts.regA, opts.regX))
	case bpf.NegateA:
		return ebpfInsn(asm.Neg.Imm32(opts.regA, 0))

	case bpf.Jump:
		return ebpfInsn(asm.Ja.Label(opts.label(blk.skipToBlock(skip(i.Skip)).Label())))
	case bpf.JumpIf:
		return condToEBPF(opts, skip(i.SkipTrue), skip(i.SkipFalse), blk, i.Cond, func(jo asm.JumpOp, label string) asm.Instructions {
			// eBPF immediates are signed, zero extend into temp register
			if int32(i.Val) < 0 {
				return asm.Instructions{
					asm.Mov.Imm32(opts.regTmp, int32(i.Val)),
					jo.Reg(opts.regA, opts.regTmp, label),
				}
			}

			return asm.Instructions{jo.Imm(opts.regA, int32(i.Val), label)}
		})
	case bpf.JumpIfX:
		return condToEBPF(opts, skip(i.SkipTrue), skip(i.SkipFalse), blk, i.Cond, func(jo asm.JumpOp, label string) asm.Instructions {
			return asm.Instructions{jo.Reg(opts.regA, opts.regX, label)}
		})

	case bpf.RetA:
		return ebpfInsn(
			asm.Mov.Reg32(opts.Result, opts.regA),
			asm.Ja.Label(opts.ResultLabel),
		)
	case bpf.RetConstant:
		return ebpfInsn(
			asm.Mov.Imm32(opts.Result, int32(i.Val)),
			asm.Ja.Label(opts.ResultLabel),
		)

	case bpf.TXA:
		return ebpfInsn(asm.Mov.Reg32(opts.regA, opts.regX))
	case bpf.TAX:
		return ebpfInsn(asm.Mov.Reg32(opts.regX, opts.regA))

	case packetGuardAbsolute:
		return ebpfInsn(
			asm.Mov.Reg(opts.regTmp, opts.PacketStart),
			asm.Add.Imm(opts.regTmp, i.end),
			asm.JGT.Reg(opts.regTmp, opts.PacketEnd, opts.label(noMatchLabel)),
		)
	case packetGuardIndirect:
		return ebpfInsn(
			// Sign extend RegX to 64bits so we can do signed ALU operations.
			asm.Mov.Reg(opts.regIndirect, opts.regX),
			asm.LSh.Imm(opts.regIndirect, 32),
			asm.ArSh.Imm(opts.regIndirect, 32),

			// Check maxStartOffset()
			asm.Add.Imm(opts.regIndirect, i.start),
			asm.JGE.Imm(opts.regIndirect, i.maxStartOffset(), opts.label(noMatchLabel)),

			// packet_start + signed x + start
			// This will have a smin_value >= 0
			asm.Add.Reg(opts.regIndirect, opts.PacketStart),

			// different reg (so actual load picks offset), but same verifier context id
			asm.Mov.Reg(opts.regTmp, opts.regIndirect),
			asm.Add.Imm(opts.regTmp, i.length()),
			asm.JGT.Reg(opts.regTmp, opts.PacketEnd, opts.label(noMatchLabel)),
		)

	case checkXNotZero:
		return ebpfInsn(asm.JEq.Imm(opts.regX, 0, opts.label(noMatchLabel)))

	default:
		return nil, errors.Errorf("unsupported instruction %v", insn)
	}

}

type packetRead func(src asm.Register, offset int16, size asm.Size) asm.Instructions

func packetLoad(opts ebpfOpts, src asm.Register, offset uint32, size int, makeRead packetRead) (asm.Instructions, error) {
	// cBPF supports 32 bit signed offsets, but eBPF only 16 bit natively.
	if int32(offset) > math.MaxInt16 || int32(offset) < math.MinInt16 {
		return append(asm.Instructions{
			asm.Mov.Reg(opts.regTmp, src),
			// cBPF offsets are signed, casting to int32 is safe.
			asm.Add.Imm(opts.regTmp, int32(offset)),
		}, makeRead(opts.regTmp, 0, sizeToEBPF[size])...), nil
	}

	return makeRead(src, int16(offset), sizeToEBPF[size]), nil
}

func appendNtoh(reg asm.Register, size asm.Size, insns ...asm.Instruction) asm.Instructions {
	if size == asm.Byte {
		return insns
	}

	// BPF_FROM_BE should be a nop on big endian architectures
	return append(insns, asm.HostTo(asm.BE, reg, size))
}

func condToEBPF(opts ebpfOpts, skipTrue, skipFalse skip, blk *block, cond bpf.JumpTest, insn func(jo asm.JumpOp, label string) asm.Instructions) (asm.Instructions, error) {
	var condToJump = map[bpf.JumpTest]asm.JumpOp{
		bpf.JumpEqual:          asm.JEq,
		bpf.JumpNotEqual:       asm.JNE,
		bpf.JumpGreaterThan:    asm.JGT,
		bpf.JumpLessThan:       asm.JLT,
		bpf.JumpGreaterOrEqual: asm.JGE,
		bpf.JumpLessOrEqual:    asm.JLE,
		bpf.JumpBitsSet:        asm.JSet,
		// BitsNotSet doesn't map to anything nicely
	}

	trueLabel := opts.label(blk.skipToBlock(skipTrue).Label())
	falseLabel := opts.label(blk.skipToBlock(skipFalse).Label())

	// no skipFalse, we only have to explicitly jump to one block
	trueOnly := skipFalse == 0

	// No native BitsNotSet, convert to BitsSet
	if cond == bpf.JumpBitsNotSet {
		cond = bpf.JumpBitsSet

		trueLabel, falseLabel = falseLabel, trueLabel

		trueOnly = false
	}

	if trueOnly {
		return insn(condToJump[cond], trueLabel), nil
	}

	return append(
		insn(condToJump[cond], trueLabel),
		asm.Ja.Label(falseLabel),
	), nil
}

func ebpfInsn(insns ...asm.Instruction) (asm.Instructions, error) {
	return insns, nil
}
