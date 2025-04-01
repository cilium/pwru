// Package cbpfc implements a cBPF (classic BPF) to eBPF
// (extended BPF, not be confused with cBPF extensions) compiler.
//
// cbpfc can compile cBPF filters to:
//   - C, which can be compiled to eBPF with Clang
//   - eBPF
//
// Both the C and eBPF output are intended to be accepted by the kernel verifier:
//   - All packet loads are guarded with runtime packet length checks
//   - RegA and RegX are zero initialized as required
//   - Division by zero is guarded by runtime checks
//
// The generated C / eBPF is intended to be embedded into a larger C / eBPF program.
package cbpfc

import (
	"fmt"
	"sort"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

// maxPacketOffset is the maximum packet offset the verifier allows.
// https://elixir.bootlin.com/linux/v5.14.8/source/kernel/bpf/verifier.c#L3223
const maxPacketOffset = 0xFFFF

// Map conditionals to their inverse
var condToInverse = map[bpf.JumpTest]bpf.JumpTest{
	bpf.JumpEqual:          bpf.JumpNotEqual,
	bpf.JumpNotEqual:       bpf.JumpEqual,
	bpf.JumpGreaterThan:    bpf.JumpLessOrEqual,
	bpf.JumpLessThan:       bpf.JumpGreaterOrEqual,
	bpf.JumpGreaterOrEqual: bpf.JumpLessThan,
	bpf.JumpLessOrEqual:    bpf.JumpGreaterThan,
	bpf.JumpBitsSet:        bpf.JumpBitsNotSet,
	bpf.JumpBitsNotSet:     bpf.JumpBitsSet,
}

// pos stores the absolute position of a cBPF instruction
type pos uint

// skips store cBPF jumps, which are relative
type skip uint

// instruction wraps a bpf instruction with it's
// original position
type instruction struct {
	bpf.Instruction
	id pos
}

func (i instruction) String() string {
	return fmt.Sprintf("%d: %v", i.id, i.Instruction)
}

// block contains a linear flow on instructions:
//   - Nothing jumps into the middle of a block
//   - Nothing jumps out of the middle of a block
//
// A block may start or end with any instruction, as any instruction
// can be the target of a jump.
//
// A block also knows what blocks it jumps to. This forms a DAG of blocks.
type block struct {
	// Should not be directly modified, instead copy instructions to new slice
	insns []instruction

	// Map of absolute instruction positions the last instruction
	// of this block can jump to, to the corresponding block
	jumps map[pos]*block

	// id of the instruction that started this block
	// Unique, but not guaranteed to match insns[0].id after blocks are modified
	id pos
}

// newBlock creates a block with copy of insns
func newBlock(insns []instruction) *block {
	return &block{
		insns: insns,
		jumps: make(map[pos]*block),
		id:    insns[0].id,
	}
}

func (b *block) Label() string {
	return fmt.Sprintf("block_%d", b.id)
}

func (b *block) skipToPos(s skip) pos {
	return b.last().id + 1 + pos(s)
}

// Get the target block of a skip
func (b *block) skipToBlock(s skip) *block {
	return b.jumps[b.skipToPos(s)]
}

func (b *block) last() instruction {
	return b.insns[len(b.insns)-1]
}

// packetGuard is a "fake" cBPF instruction
// that checks packet bounds before data is read from the packet.
type packetGuard interface {
	bpf.Instruction

	// Extend returns a guard that is the union of the current guard and o.
	extend(o packetGuard) packetGuard

	// Restrict returns a guard that is the intersection of the current guard and o.
	restrict(o packetGuard) packetGuard

	// Adjust any instructions that are covered by this guard as required.
	adjustInsns(insns []instruction)
}

// packetGuardAbsolute checks packet bounds for absolute packet loads (constant offset).
// We only need to track the last / greatest byte read to ensure it isn't past the packet end.
type packetGuardAbsolute struct {
	// The furthest (exclusive) byte read.
	end int32
}

func newPacketGuardAbsolute(off uint32, size int) packetGuardAbsolute {
	if off > maxPacketOffset {
		panic("can't create absolute packet guard for offset")
	}

	// Absolute offsets are limited to maxPacketOffset so this can't overflow.
	return packetGuardAbsolute{int32(off) + int32(size)}
}

func (a packetGuardAbsolute) extend(o packetGuard) packetGuard {
	n := a
	if b := o.(packetGuardAbsolute); b.end > a.end {
		n.end = b.end
	}
	return n
}

func (a packetGuardAbsolute) restrict(o packetGuard) packetGuard {
	n := a
	if b := o.(packetGuardAbsolute); b.end < a.end {
		n.end = b.end
	}
	return n
}

// We don't need to adjust instructions for absolute guards.
func (a packetGuardAbsolute) adjustInsns(insns []instruction) {}

// Assemble implements the Instruction Assemble method.
func (p packetGuardAbsolute) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// packetGuardIndirect checks packet bounds for indirect packet loads (RegX + constant offset).
// RegX and offset are both allowed to be negative, but RegX + Offset must be >= 0 (the verifier does not allow
// adding negative offsets to packet pointers).
//
// This requires tracking both the first and last byte read (relative to RegX) to check:
//   - RegX + start >= 0
//   - RegX + end < maxPacketOffset
//   - packet_start + RegX + end < packet_end
//
// Bounds / range information is propagated in the verifier by copying a packet pointer,
// adding a constant (which yields a "derived" packet pointer with the same ID), and checking it against the packet_end.
// Subsequent LoadIndirects that are covered by this guard need to use a packet pointer with same ID as the guard to
// take advantage of the bounds.
// Ideally we would use packet_start + RegX and let each LoadIndirect instruction add its own offset,
// but the verifier doesn't allow the use of packet pointers with a negative offset (even if the offset
// would make the read positive: https://elixir.bootlin.com/linux/v5.14.12/source/kernel/bpf/verifier.c#L3287)
//
// So instead we check:
//   - RegX + start >= 0
//   - RegX + start < maxPacketOffset - length
//   - packet_start + RegX + start + length < packet_end
//
// This lets us reuse packet_start + RegX + start as the packet pointer for LoadIndirect,
// but means we need to rewrite the offsets of LoadIndirect instructions covered by this guard to subtract length.
type packetGuardIndirect struct {
	// First byte read (inclusive).
	start int32
	// Last byte read (exclusive).
	// int64 to avoid overflows with INT32_MAX + size
	end int64
}

func newPacketGuardIndirect(off uint32, size int) packetGuardIndirect {
	// cBPF offsets are uint32, but are signed in reality
	// LoadIndirect offsets are encoded as uint32 by x/net/bpf, but are signed in reality.
	// Unlike LoadAbsolute, restrictions only apply to RegX + Offset and not Offset alone,
	// so we have to allow INT32_MAX / INT32_MIN offsets.
	return packetGuardIndirect{
		start: int32(off),
		end:   int64(int32(off)) + int64(size),
	}
}

func (a packetGuardIndirect) extend(o packetGuard) packetGuard {
	b := o.(packetGuardIndirect)

	// A 0 guard means no guard, we shouldn't extend it to cover {0,0}
	if a == (packetGuardIndirect{}) {
		return b
	}
	if b == (packetGuardIndirect{}) {
		return a
	}

	n := a

	if b.start < a.start {
		n.start = b.start
	}
	if b.end > a.end {
		n.end = b.end
	}

	return n
}

func (a packetGuardIndirect) restrict(o packetGuard) packetGuard {
	b := o.(packetGuardIndirect)

	// A 0 guard means no guard, that restricts everything to no guard.
	if a == (packetGuardIndirect{}) || b == (packetGuardIndirect{}) {
		return packetGuardIndirect{}
	}

	n := a

	if b.start > a.start {
		n.start = b.start
	}
	if b.end < a.end {
		n.end = b.end
	}

	return n
}

// int32(RegX) + p.start must be < to maxStartOffset().
// This checks that it is positive, and int32(RegX) + p.end doesn't exceed maxPacketOffset.
// Returns 0 (check will always be false) if there is no way for the start and end of the guard to be < maxPacketOffset.
func (p packetGuardIndirect) maxStartOffset() int32 {
	length := p.end - int64(p.start)
	// If length exceeds maxPacketOffset, there's no way for RegX + start >= 0 and RegX + end < maxPacketOffset.
	// Return 0 so the check fails, and we return noMatch.
	if length > maxPacketOffset {
		return 0
	}

	// +1 as it needs to be strictly less than.
	// This lets us return 0 above to get noMatch.
	return int32(maxPacketOffset) - int32(length) + 1
}

// packet_start + (int32(x) + p.start) + p.length() must be <= packet_end.
// This lets us reuse the (int32(x) + p.start) from the maxStartOffset() check, to keep the bounds info.
func (p packetGuardIndirect) length() int32 {
	// This can overflow, but it doesn't matter as we'll already have checked maxStartOffset()
	// and caught the overflow there.
	return int32(p.end - int64(p.start))
}

// Once we've determined the guard that applies for a given set of insns,
// asjust the offsets so they're relative to the smallest / start of the guard.
func (p packetGuardIndirect) adjustInsns(insns []instruction) {
	for i := range insns {
		switch insn := insns[i].Instruction.(type) {
		case bpf.LoadIndirect:
			insns[i].Instruction = bpf.LoadIndirect{
				Off:  uint32(int32(insn.Off) - p.start),
				Size: insn.Size,
			}
		}
	}
}

// Assemble implements the Instruction Assemble method.
func (p packetGuardIndirect) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// checksXNotZero is a "fake" instruction
// that returns no match if X is 0
type checkXNotZero struct {
}

// Assemble implements the Instruction Assemble method.
func (c checkXNotZero) Assemble() (bpf.RawInstruction, error) {
	return bpf.RawInstruction{}, errors.Errorf("unsupported")
}

// compile compiles a cBPF program to an ordered slice of blocks, with:
// - Registers zero initialized as required
// - Required packet access guards added
// - JumpIf and JumpIfX instructions normalized (see normalizeJumps)
func compile(insns []bpf.Instruction) ([]*block, error) {
	err := validateInstructions(insns)
	if err != nil {
		return nil, err
	}

	instructions := toInstructions(insns)

	normalizeJumps(instructions)

	// Split into blocks
	blocks, err := splitBlocks(instructions)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to compute blocks")
	}

	// Initialize registers
	err = initializeMemory(blocks)
	if err != nil {
		return nil, err
	}

	// Check we don't divide by zero
	err = addDivideByZeroGuards(blocks)
	if err != nil {
		return nil, err
	}

	rewriteLargePacketOffsets(&blocks)

	// Guard packet loads
	addAbsolutePacketGuards(blocks)
	addIndirectPacketGuards(blocks)

	return blocks, nil
}

// validateInstructions checks the instructions are valid, and we support them
func validateInstructions(insns []bpf.Instruction) error {
	// Can't do anything meaningful with no instructions
	if len(insns) == 0 {
		return errors.New("can't compile 0 instructions")
	}

	for pc, insn := range insns {
		// Assemble does some input validation
		_, err := insn.Assemble()
		if err != nil {
			return errors.Errorf("can't assemble instruction %d: %v", pc, insn)
		}

		switch i := insn.(type) {
		case bpf.RawInstruction:
			return errors.Errorf("unsupported instruction %d: %v", pc, insn)

		// Negative constant offsets are used for extensions (and if they're supported, x/net/bpf will parse them)
		// and other packet addressing modes we don't support: https://elixir.bootlin.com/linux/v5.14.10/source/kernel/bpf/core.c#L65
		case bpf.LoadAbsolute:
			if int32(i.Off) < 0 {
				return errors.Errorf("LoadAbsolute negative offset %v", int32(i.Off))
			}
		case bpf.LoadMemShift:
			if int32(i.Off) < 0 {
				return errors.Errorf("LoadMemShift negative offset %v", int32(i.Off))
			}

		case bpf.LoadExtension:
			switch i.Num {
			case bpf.ExtLen:
				break
			default:
				return errors.Errorf("unsupported BPF extension %d: %v", pc, insn)
			}
		}
	}

	return nil
}

func toInstructions(insns []bpf.Instruction) []instruction {
	instructions := make([]instruction, len(insns))

	for pc, insn := range insns {
		instructions[pc] = instruction{
			Instruction: insn,
			id:          pos(pc),
		}
	}

	return instructions
}

// normalizeJumps normalizes conditional jumps to always use skipTrue:
// Jumps that only use skipTrue (skipFalse == 0) are unchanged.
// Jumps that use both skipTrue and skipFalse are unchanged.
// Jumps that only use skipFalse (skipTrue == 0) are inverted to only use skipTrue.
func normalizeJumps(insns []instruction) {
	for pc := range insns {
		switch i := insns[pc].Instruction.(type) {
		case bpf.JumpIf:
			if !shouldInvert(i.SkipTrue, i.SkipFalse) {
				continue
			}

			insns[pc].Instruction = bpf.JumpIf{Cond: condToInverse[i.Cond], Val: i.Val, SkipTrue: i.SkipFalse, SkipFalse: i.SkipTrue}

		case bpf.JumpIfX:
			if !shouldInvert(i.SkipTrue, i.SkipFalse) {
				continue
			}

			insns[pc].Instruction = bpf.JumpIfX{Cond: condToInverse[i.Cond], SkipTrue: i.SkipFalse, SkipFalse: i.SkipTrue}
		}
	}
}

// Check if a conditional jump should be inverted
func shouldInvert(skipTrue, skipFalse uint8) bool {
	return skipTrue == 0 && skipFalse != 0
}

// Traverse instructions until end of first block. Target is absolute start of block.
// Return block-relative jump targets
func visitBlock(insns []instruction, target pos) (*block, []skip) {
	for pc, insn := range insns {
		// Relative jumps from this instruction
		var skips []skip

		switch i := insn.Instruction.(type) {
		case bpf.Jump:
			skips = []skip{skip(i.Skip)}
		case bpf.JumpIf:
			skips = []skip{skip(i.SkipTrue), skip(i.SkipFalse)}
		case bpf.JumpIfX:
			skips = []skip{skip(i.SkipTrue), skip(i.SkipFalse)}

		case bpf.RetA, bpf.RetConstant:
			// No extra targets to visit

		default:
			// Regular instruction, next please!
			continue
		}

		// every insn including this one
		return newBlock(insns[:pc+1]), skips
	}

	// Try to fall through to next block
	return newBlock(insns), []skip{0}
}

// splitBlocks splits the cBPF into an ordered list of blocks.
//
// The blocks are preserved in the order they are found as this guarantees that
// a block only targets later blocks (cBPF jumps are positive, relative offsets).
// This also mimics the layout of the original cBPF, which is good for debugging.
func splitBlocks(instructions []instruction) ([]*block, error) {
	// Blocks we've visited already
	blocks := []*block{}

	// map of targets to blocks that target them
	// target 0 is for the base case
	targets := map[pos][]*block{
		0: nil,
	}

	// As long as we have un visited targets
	for len(targets) > 0 {
		sortedTargets := sortTargets(targets)

		// Get the first one (not really breadth first, but close enough!)
		target := sortedTargets[0]

		end := len(instructions)
		// If there's a next target, ensure we stop before it
		if len(sortedTargets) > 1 {
			end = int(sortedTargets[1])
		}

		next, nextSkips := visitBlock(instructions[target:end], target)

		// Add skips to our list of things to visit
		for _, s := range nextSkips {
			// Convert relative skip to absolute pos
			t := next.skipToPos(s)

			if t >= pos(len(instructions)) {
				return nil, errors.Errorf("instruction %v flows past last instruction", next.last())
			}

			targets[t] = append(targets[t], next)
		}

		jmpBlocks := targets[target]

		// Mark all the blocks that jump to the block we've just visited as doing so
		for _, jmpBlock := range jmpBlocks {
			jmpBlock.jumps[target] = next
		}

		blocks = append(blocks, next)

		// Target is now a block!
		delete(targets, target)
	}

	return blocks, nil
}

// sortTargets sorts the target positions (keys), lowest first
func sortTargets(targets map[pos][]*block) []pos {
	keys := make([]pos, len(targets))

	i := 0
	for k := range targets {
		keys[i] = k
		i++
	}

	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	return keys
}

// addDivideByZeroGuards adds runtime guards / checks to ensure
// the program returns no match when it would otherwise divide by zero.
func addDivideByZeroGuards(blocks []*block) error {
	isDivision := func(op bpf.ALUOp) bool {
		return op == bpf.ALUOpDiv || op == bpf.ALUOpMod
	}

	// Is RegX known to be none 0 at the start of each block
	// We can't divide by RegA, only need to check RegX.
	xNotZero := make(map[*block]bool)

	for _, block := range blocks {
		notZero := xNotZero[block]

		// newInsns to replace those in the block
		newInsns := []instruction{}
		for _, insn := range block.insns {
			switch i := insn.Instruction.(type) {
			case bpf.ALUOpConstant:
				if isDivision(i.Op) && i.Val == 0 {
					return errors.Errorf("instruction %v divides by 0", insn)
				}
			case bpf.ALUOpX:
				if isDivision(i.Op) && !notZero {
					newInsns = append(newInsns, instruction{Instruction: checkXNotZero{}})
					notZero = true
				}
			}

			newInsns = append(newInsns, insn)

			// check if X clobbered - check is invalidated
			if memWrites(insn.Instruction).regs[bpf.RegX] {
				notZero = false
			}
		}
		block.insns = newInsns

		// update the status of every block this one jumps to
		for _, target := range block.jumps {
			targetNotZero, ok := xNotZero[target]
			if !ok {
				xNotZero[target] = notZero
				continue
			}

			// x needs to be not zero from every possible path
			xNotZero[target] = targetNotZero && notZero
		}
	}

	return nil
}

// rewriteLargePacketOffsets replaces packet loads that have constant offsets
// greater than the verifier allows with return 0 (no match) to mimick
// what the kernel does for cBPF.
// While cBPF allows bigger offsets, in practice they cannot match a packet.
// This doesn't work for LoadIndirect as the actual offset is LoadIndirect.Off + RegX,
// we instead rely on runtime checks (see packetGuardIndirect).
func rewriteLargePacketOffsets(blocks *[]*block) {
	// All blocks are reachable when we start.
	// But some blocks can become unreachable once we've rewritten load instructions to returns.
	// The verifier rejects unreachable instructions, track how many other blocks go to a given block
	// so we can remove newly unreachable blocks.
	blockRefs := make(map[*block]int)

	var newBlocks []*block

	for i, block := range *blocks {
		// No other blocks jump into this block anymore, skip it.
		if i != 0 && blockRefs[block] == 0 {
			continue
		}
		newBlocks = append(newBlocks, block)

		for _, insn := range block.insns {
			var (
				offset uint32
				size   int
			)

			// LoadIndirect is handled by runtime checks as only RegX + offset is subject to maxPacketOffset.
			switch i := insn.Instruction.(type) {
			case bpf.LoadAbsolute:
				offset = i.Off
				size = i.Size
			case bpf.LoadMemShift:
				offset = i.Off
				size = 1
			default:
				continue
			}

			// A packetGuard will have to add size to the packet pointer, so it counts towards the limit.
			// We've already validate offset isn't signed, so this can't overflow.
			if offset+uint32(size) > maxPacketOffset {
				// Mimick an out of bounds load in cBPF, returning 0 / no match.
				// The block now unconditionally returns, the other instructions in it don't matter.
				block.insns = []instruction{
					{Instruction: bpf.RetConstant{Val: 0}},
				}

				// This block doesn't jump to any others anymore.
				block.jumps = nil

				break
			}
		}

		// cBPF can't jump backwards, so we can build this up as we go.
		for _, target := range block.jumps {
			blockRefs[target]++
		}
	}

	*blocks = newBlocks
}

// addAbsolutePacketGuard adds required packet guards for absolute packet accesses to blocks.
func addAbsolutePacketGuards(blocks []*block) {
	addPacketGuards(blocks, packetGuardOpts{
		requiredGuard: func(insns []instruction) requiredGuard {
			var biggestGuard packetGuard = packetGuardAbsolute{}

			for _, insn := range insns {
				switch i := insn.Instruction.(type) {
				case bpf.LoadAbsolute:
					biggestGuard = biggestGuard.extend(newPacketGuardAbsolute(i.Off, i.Size))
				case bpf.LoadMemShift:
					biggestGuard = biggestGuard.extend(newPacketGuardAbsolute(i.Off, 1))
				}
			}

			// Guard covers all instructions.
			return requiredGuard{
				guard:       biggestGuard,
				alwaysValid: true,
			}
		},

		zeroGuard: func() packetGuard {
			return packetGuardAbsolute{}
		},
	})
}

// addIndirectPacketGuard adds required packet guards for indirect packet accesses to blocks.
func addIndirectPacketGuards(blocks []*block) {
	addPacketGuards(blocks, packetGuardOpts{
		requiredGuard: func(insns []instruction) requiredGuard {
			var (
				insnCount    int
				biggestGuard packetGuard = packetGuardIndirect{}
			)

			for _, insn := range insns {
				insnCount++

				switch i := insn.Instruction.(type) {
				case bpf.LoadIndirect:
					biggestGuard = biggestGuard.extend(newPacketGuardIndirect(i.Off, i.Size))
				}

				// Check if we clobbered x - this invalidates the guard
				if memWrites(insn.Instruction).regs[bpf.RegX] {
					return requiredGuard{
						guard:         biggestGuard,
						validForInsns: insnCount,
					}
				}
			}

			return requiredGuard{
				guard:       biggestGuard,
				alwaysValid: true,
			}
		},

		zeroGuard: func() packetGuard {
			return packetGuardIndirect{}
		},
	})
}

type packetGuardOpts struct {
	// requiredGuard returns the packetGuard needed by insns, and what insns it is valid for.
	requiredGuard func(insns []instruction) requiredGuard

	// zeroGuard returns an empty guard of the right type.
	zeroGuard func() packetGuard
}

type requiredGuard struct {
	guard packetGuard

	// The guard covers all the requested instructions,
	// and is still valid afterwards.
	alwaysValid bool

	// The guard covers n instructions,
	// and isn't valid for the subsequent n+1: instructions (eg RegX was clobbered for indirect guards).
	validForInsns int
}

// addPacketGuards adds packet guards as required.
//
// Traversing the DAG of blocks (by visiting the blocks a block jumps to),
// we know all packet guards that exist at the start of a given block.
// We can check if the block requires a longer / bigger guard than
// the shortest / least existing guard.
func addPacketGuards(blocks []*block, opts packetGuardOpts) {
	// Guards in effect at the start of each block
	// Can't jump backwards so we only need to traverse blocks once
	guards := make(map[*block][]packetGuard)

	for _, block := range blocks {
		blockGuard := addBlockGuards(block, leastGuard(opts.zeroGuard(), guards[block]), opts)

		for _, target := range block.jumps {
			guards[target] = append(guards[target], blockGuard)
		}
	}
}

// addBlockGuards add the guards required for the instructions in block.
func addBlockGuards(block *block, currentGuard packetGuard, opts packetGuardOpts) packetGuard {
	insns := block.insns
	block.insns = nil

	for len(insns) != 0 {
		required := opts.requiredGuard(insns)

		// Need a bigger guard for these insns. Don't use the bigger guard on it's own,
		// extend the current one so we keep as much information as we have.
		if newGuard := currentGuard.extend(required.guard); newGuard != currentGuard {
			currentGuard = newGuard

			// Last guard we need for this block -> what our children / target blocks will start with
			if required.alwaysValid {
				// If packets must go through a bigger guard (guaranteed guard) to match, we can use the guaranteed guard here,
				// without changing the return value of the program:
				//   - packets smaller than the guaranteed guard cannot match anyways, we can safely reject them earlier
				//   - packets bigger than the guaranteed guard won't be affected by it
				currentGuard = currentGuard.extend(guaranteedGuard(block.jumps, opts))
			}

			block.insns = append(block.insns, instruction{Instruction: currentGuard})
		}

		coveredInsns := insns
		if !required.alwaysValid {
			coveredInsns = insns[:required.validForInsns]
		}

		currentGuard.adjustInsns(coveredInsns)
		block.insns = append(block.insns, coveredInsns...)

		if required.alwaysValid {
			// Guard covers remainder of block, and is still valid at the end.
			return currentGuard
		} else {
			// Guard isn't valid anymore.
			currentGuard = opts.zeroGuard()
			insns = insns[required.validForInsns:]
		}
	}

	return currentGuard
}

// guaranteedGuard performs a recursive depth first search of blocks in target to determine
// the greatest packet guard that must be made for a packet to match
//
// If the DAG of blocks needs these packet guards:
//
//	     [4]
//	    /   \
//	false   [6]
//	       /   \
//	    true   [8]
//	          /   \
//	      false   true
//
// A packet can only match ("true") by going through guards 4 and 6. It does not have to go through guard 8.
// guaranteedGuard would return 6.
func guaranteedGuard(targets map[pos]*block, opts packetGuardOpts) packetGuard {

	// Inner implementation - Uses memoization
	return guaranteedGuardCached(targets, opts, make(map[*block]packetGuard))
}

// 'cache' is used in order to not calculate guard more than once for the same block.
func guaranteedGuardCached(targets map[pos]*block, opts packetGuardOpts, cache map[*block]packetGuard) packetGuard {
	targetGuards := []packetGuard{}

	for _, target := range targets {
		// Block can't match the packet, ignore it
		if blockNeverMatches(target) {
			continue
		}
		if guard, ok := cache[target]; ok {
			targetGuards = append(targetGuards, guard)
			continue
		}

		required := opts.requiredGuard(target.insns)

		// Guard invalidated by block, stop exploring
		if !required.alwaysValid {
			targetGuards = append(targetGuards, required.guard)
			continue
		}

		guard := required.guard.extend(guaranteedGuardCached(target.jumps, opts, cache))

		cache[target] = guard
		targetGuards = append(targetGuards, guard)
	}

	return leastGuard(opts.zeroGuard(), targetGuards)
}

// leastGuard returns the smallest guard from guards.
// zero if there are no guards.
func leastGuard(zero packetGuard, guards []packetGuard) packetGuard {
	least := zero

	for i, guard := range guards {
		if i == 0 {
			least = guard
		} else {
			least = least.restrict(guard)
		}
	}

	return least
}

// blockNeverMatches returns true IFF the insns in block will never match the input packet
func blockNeverMatches(block *block) bool {
	for _, insn := range block.insns {
		switch i := insn.Instruction.(type) {
		case bpf.RetConstant:
			if i.Val == 0 {
				return true
			}
		}
	}

	return false
}

// memStatus represents a context defined status of registers & scratch
type memStatus struct {
	// indexed by bpf.Register
	regs    [2]bool
	scratch [16]bool
}

// merge merges this status with the other by applying policy to regs and scratch
func (r memStatus) merge(other memStatus, policy func(this, other bool) bool) memStatus {
	newStatus := memStatus{}

	for i := range newStatus.regs {
		newStatus.regs[i] = policy(r.regs[i], other.regs[i])
	}

	for i := range newStatus.scratch {
		newStatus.scratch[i] = policy(r.scratch[i], other.scratch[i])
	}

	return newStatus
}

// and merges this status with the other by logical AND
func (r memStatus) and(other memStatus) memStatus {
	return r.merge(other, func(this, other bool) bool {
		return this && other
	})
}

// and merges this status with the other by logical OR
func (r memStatus) or(other memStatus) memStatus {
	return r.merge(other, func(this, other bool) bool {
		return this || other
	})
}

// initializeMemory zero initializes all the registers that the BPF program reads from before writing to. Returns an error if any scratch memory is used uninitialized.
func initializeMemory(blocks []*block) error {
	// memory initialized at the start of each block
	statuses := make(map[*block]memStatus)

	// uninitialized memory used so far
	uninitialized := memStatus{}

	for _, block := range blocks {
		status := statuses[block]

		for _, insn := range block.insns {
			insnUninitialized := memUninitializedReads(insn.Instruction, status)
			// Check no uninitialized scratch registers are read
			for scratch, uninit := range insnUninitialized.scratch {
				if uninit {
					return errors.Errorf("instruction %v reads potentially uninitialized scratch register M[%d]", insn, scratch)
				}
			}

			uninitialized = uninitialized.or(insnUninitialized)
			status = status.or(memWrites(insn.Instruction))
		}

		// update the status of every block this one jumps to
		for _, target := range block.jumps {
			targetStatus, ok := statuses[target]
			if !ok {
				statuses[target] = status
				continue
			}

			// memory needs to be initialized from every possible path
			statuses[target] = targetStatus.and(status)
		}
	}

	// new instructions we need to prepend to initialize uninitialized registers
	initInsns := []instruction{}
	for reg, uninit := range uninitialized.regs {
		if !uninit {
			continue
		}

		initInsns = append(initInsns, instruction{
			Instruction: bpf.LoadConstant{
				Dst: bpf.Register(reg),
				Val: 0,
			},
		})
	}
	blocks[0].insns = append(initInsns, blocks[0].insns...)
	return nil
}

// memUninitializedReads returns the memory read by insn that has not yet been initialized according to initialized.
func memUninitializedReads(insn bpf.Instruction, initialized memStatus) memStatus {
	return memReads(insn).merge(initialized, func(read, init bool) bool {
		return read && !init
	})
}

// memReads returns the memory read by insn
func memReads(insn bpf.Instruction) memStatus {
	read := memStatus{}

	switch i := insn.(type) {
	case bpf.ALUOpConstant:
		read.regs[bpf.RegA] = true
	case bpf.ALUOpX:
		read.regs[bpf.RegA] = true
		read.regs[bpf.RegX] = true

	case bpf.JumpIf:
		read.regs[bpf.RegA] = true
	case bpf.JumpIfX:
		read.regs[bpf.RegA] = true
		read.regs[bpf.RegX] = true

	case bpf.LoadIndirect:
		read.regs[bpf.RegX] = true
	case bpf.LoadScratch:
		read.scratch[i.N] = true

	case bpf.NegateA:
		read.regs[bpf.RegA] = true

	case bpf.RetA:
		read.regs[bpf.RegA] = true

	case bpf.StoreScratch:
		read.regs[i.Src] = true

	case bpf.TAX:
		read.regs[bpf.RegA] = true
	case bpf.TXA:
		read.regs[bpf.RegX] = true
	}

	return read
}

// memWrites returns the memory written by insn
func memWrites(insn bpf.Instruction) memStatus {
	write := memStatus{}

	switch i := insn.(type) {
	case bpf.ALUOpConstant:
		write.regs[bpf.RegA] = true
	case bpf.ALUOpX:
		write.regs[bpf.RegA] = true

	case bpf.LoadAbsolute:
		write.regs[bpf.RegA] = true
	case bpf.LoadConstant:
		write.regs[i.Dst] = true
	case bpf.LoadExtension:
		write.regs[bpf.RegA] = true
	case bpf.LoadIndirect:
		write.regs[bpf.RegA] = true
	case bpf.LoadMemShift:
		write.regs[bpf.RegX] = true
	case bpf.LoadScratch:
		write.regs[i.Dst] = true

	case bpf.NegateA:
		write.regs[bpf.RegA] = true

	case bpf.StoreScratch:
		write.scratch[i.N] = true

	case bpf.TAX:
		write.regs[bpf.RegX] = true
	case bpf.TXA:
		write.regs[bpf.RegA] = true
	}

	return write
}
