package libpcap

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

/*
Steps:
1. Find the injection position, which is the bpf_printk call
2. Make some necessary preparations for the injection
3. Compile the filter expression into ebpf instructions
4. Inject the instructions
*/
func InjectFilter(program *ebpf.ProgramSpec, filterExpr string) (err error) {
	/*
	   First let's mark references and symbols for the jump instructions.
	   This is even required when filterExpr is empty, because we still
	   need to remove the bpf_printk call in that case, which breaks the
	   jump instructions as well.
	*/
	injectIdx := 0
	for idx, inst := range program.Instructions {
		// In the kprobe_pwru.c, we deliberately put a bpf_printk call to mark the injection position, see the comments over there.
		if inst.OpCode.JumpOp() == asm.Call && inst.Constant == int64(asm.FnTracePrintk) {
			injectIdx = idx
			break
		}

		/*
			As we are injecting a bunch of instructions into the
			program, the jump instructions are likely to require
			adjustments on their pc-related offsets. For example,
			we have the original bpf program as follows:

			26: 	 if r9 >= r8 goto +384 <LBB1_39>
			...
			96: 	 call bpf_trace_printk#6
			...

			After the injection, the instruction No.96 is replaced
			by multiple instructions, leaving the instruction No.26
			jumping to a wrong instruction. The offset should be
			adjusted accordingly!

			We solve this problem smart way by using references and
			symbols. The code below sets -1 to the affected jump
			instructions' offsets, adds necessary symbols and
			references, let cilium/ebpf collectionLoader adjust the
			offsets according to these additional information. This
			way, we don't have to calculate the new offsets by
			hand, which is extremely likely to mess up.
		*/
		if inst.OpCode.Class().IsJump() {
			// Zero jump offset implies a function call, leave it alone
			if inst.Offset == 0 {
				continue
			}

			// If there already is a reference and corresponding
			// symbol, we don't have to create new symbol, just set -1
			// to the offset so that cilium/ebpf loader can adjust it.
			if inst.Reference() != "" {
				program.Instructions[idx].Offset = -1
				continue
			}

			var gotoIns *asm.Instruction
			iter := asm.Instructions(program.Instructions[idx+1:]).Iterate()
			for iter.Next() {
				if int16(iter.Offset) == inst.Offset {
					gotoIns = iter.Ins
					break
				}
			}
			if gotoIns == nil {
				return errors.New("Cannot find the jump target")
			}
			symbol := gotoIns.Symbol()
			if symbol == "" {
				symbol = fmt.Sprintf("PWRU_%d", idx)
				*gotoIns = gotoIns.WithSymbol(symbol)
			}
			program.Instructions[idx] = program.Instructions[idx].WithReference(symbol)
			program.Instructions[idx].Offset = -1
		}
	}
	if injectIdx == 0 {
		return errors.New("Cannot find the injection position")
	}

	if filterExpr == "" {
		/*
		   No need to inject anything, just remove the bpf_printk call
		   to avoid the unnecessary overhead.

		   bpf_printk() compiles to 5 instructions from index idx-4 to
		   idx: the former 4 are setting up registers from R1 to R4,
		   the last one calls printk().

		   But we can't delete former 4 instructions, otherwise we'll
		   hit verifier with "R1 !read_ok"; they're required to stay
		   there for register initialization.
		*/
		program.Instructions = append(program.Instructions[:injectIdx],
			program.Instructions[injectIdx+1:]...,
		)
		return
	}

	/*
		Conversion from cbpf to ebpf requires indication of the packet
		start and end positions. These two position should be held by
		two registers, thanks to the `bpf_printk("..", start, end)`
		statement, which makes it clear that start is at R3 and end is
		at R4.
		The code below searches the instructions prior to the
		injection position to find the registers holding the packet
		start and end positions, by looking for the mov instructions
		targeting R3 and R4.
	*/
	var (
		dataReg    asm.Register = 255
		dataEndReg asm.Register = 255
	)
	for idx := injectIdx - 1; idx >= 0; idx-- {
		inst := program.Instructions[idx]
		if inst.OpCode.ALUOp() == asm.Mov {
			if inst.Dst == asm.R3 {
				dataReg = inst.Src
			} else if inst.Dst == asm.R4 {
				dataEndReg = inst.Src
			}
		}
		if dataReg != 255 && dataEndReg != 255 {
			break
		}
	}
	if dataReg == 255 || dataEndReg == 255 {
		return errors.New("Cannot find the data / data_end registers")
	}

	filterEbpf, err := CompileEbpf(filterExpr, cbpfc.EBPFOpts{
		PacketStart: dataReg,
		PacketEnd:   dataEndReg,
		// R4 is safe to use, because at the injection position, we are
		// originally preparing to perform a bpf-helper func call with 4
		// arguments, which leaves r0, r1, r2, r3 and r4 registers ready
		// to use.
		Result:      asm.R4,
		ResultLabel: "result",
		// Same reason stated above, r0, r1, r2, r3 are safe to use.
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "filter",
		// In the kprobe_pwru.c:handle_everything, the first line of
		// code `struct event_t event = {}` initializes stack [r10-136,
		// r10-16] with zero value, so during the filtering stage, this
		// stack area is safe to use. Here we use stack from -40
		// because -32, -24, -16 are reserved for pcap-filter ebpf, see
		// the comments in compile.go
		StackOffset: -40,
	})
	if err != nil {
		return
	}
	/*
					;       bpf_printk("%d %d", data, data_end);
		    injectIdx-4 ->	    88:       r1 = 54 ll
					    90:       r2 = 6
					    91:       r3 = r9
					    92:       r4 = r8
		    injectIdx ->	    93:       call 6
					;       return filter_pcap(skb) && filter_meta(skb);
		    injectIdx+1 ->	    94:       if r9 >= r8 goto +384 <LBB1_39>

		    [injectIdx-4:injectIdx] is compiled from bpf_printk();
		    [injectIdx+1] is from `return data < data_end` statement;
		    both statements shall be replaced by pcap filter instructions.
	*/
	program.Instructions = append(program.Instructions[:injectIdx-4],
		append(filterEbpf, program.Instructions[injectIdx+2:]...)...,
	)

	return nil
}
