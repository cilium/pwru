package elibpcap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
)

/*
#cgo LDFLAGS: -L/usr/local/lib -lpcap
#include <stdlib.h>
#include <pcap.h>
*/
import "C"

type pcapBpfProgram C.struct_bpf_program

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144

	RejectAllExpr = "__reject_all__"
)

type StackOffset int

const (
	BpfReadKernelOffset StackOffset = -8 * (iota + 1)
	R1Offset
	R2Offset
	R3Offset
	R4Offset
	R5Offset
	AvailableOffset
)

/*
Steps:
1. Compile pcap expresion to cbpf using libpcap
2. Convert cbpf to ebpf using cloudflare/cbpfc
3. [!DirectRead] Convert direct memory load to bpf_probe_read_kernel call
*/
func CompileEbpf(expr string, opts Options) (insts asm.Instructions, err error) {
	if expr == RejectAllExpr {
		return asm.Instructions{
			asm.Mov.Reg(asm.R4, asm.R5), // r4 = r5 (data = data_end)
		}, nil
	}
	cbpfInsts, err := CompileCbpf(expr, opts.L2Skb)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, cbpfc.EBPFOpts{
		// skb->data is at r4, skb->data_end is at r5.
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      opts.result(),
		ResultLabel: opts.resultLabel(),
		// _skb is at R0, __skb is at R1, ___skb is at R2.
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: opts.labelPrefix(),
		StackOffset: -int(AvailableOffset),
	})
	if err != nil {
		return
	}

	return adjustEbpf(ebpfInsts, opts)
}

func CompileCbpf(expr string, l2 bool) (insts []bpf.Instruction, err error) {
	if len(expr) == 0 {
		return
	}

	pcapType := C.DLT_RAW
	if l2 {
		pcapType = C.DLT_EN10MB
	}
	pcap := C.pcap_open_dead(C.int(pcapType), MAXIMUM_SNAPLEN)
	if pcap == nil {
		return nil, fmt.Errorf("failed to pcap_open_dead: %+v\n", C.PCAP_ERROR)
	}
	defer C.pcap_close(pcap)

	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	var bpfProg pcapBpfProgram
	if C.pcap_compile(pcap, (*C.struct_bpf_program)(&bpfProg), cexpr, 1, C.PCAP_NETMASK_UNKNOWN) < 0 {
		return nil, fmt.Errorf("failed to pcap_compile '%s': %+v", expr, C.GoString(C.pcap_geterr(pcap)))
	}
	defer C.pcap_freecode((*C.struct_bpf_program)(&bpfProg))

	for _, v := range (*[bpfInstructionBufferSize]C.struct_bpf_insn)(unsafe.Pointer(bpfProg.bf_insns))[0:bpfProg.bf_len:bpfProg.bf_len] {
		insts = append(insts, bpf.RawInstruction{
			Op: uint16(v.code),
			Jt: uint8(v.jt),
			Jf: uint8(v.jf),
			K:  uint32(v.k),
		}.Disassemble())
	}
	return
}

/*
If !DirectRead, We have to adjust the ebpf instructions because verifier prevents us from
directly loading data from memory. For example, the instruction "r0 = *(u8 *)(r4 +0)"
will break verifier with error "R4 invalid mem access 'scalar", we therefore
need to convert this direct memory load to bpf_probe_read_kernel function call:

- r1 = r10  // r10 is stack top
- r1 += -8  // r1 = r10-8
- r2 = 1    // r2 = sizeof(u8)
- r3 = r4   // r4 is start of packet data, aka L3 header
- r3 += 0   // r3 = r4+0
- call bpf_probe_read_kernel  // *(r10-8) = *(u8 *)(r4+0)
- r0 = *(u8 *)(r10 -8)  // r0 = *(r10-8)

To safely borrow R1, R2 and R3 for setting up the arguments for
bpf_probe_read_kernel(), we need to save the original values of R1, R2 and R3
on stack, and restore them after the function call.
*/
func adjustEbpf(insts asm.Instructions, opts Options) (newInsts asm.Instructions, err error) {
	if !opts.DirectRead {
		replaceIdx := []int{}
		replaceInsts := map[int]asm.Instructions{}
		for idx, inst := range insts {
			if inst.OpCode.Class().IsLoad() {
				replaceIdx = append(replaceIdx, idx)
				replaceInsts[idx] = append(replaceInsts[idx],

					// Store R1, R2, R3 on stack.
					asm.StoreMem(asm.RFP, int16(R1Offset), asm.R1, asm.DWord),
					asm.StoreMem(asm.RFP, int16(R2Offset), asm.R2, asm.DWord),
					asm.StoreMem(asm.RFP, int16(R3Offset), asm.R3, asm.DWord),

					// bpf_probe_read_kernel(RFP-8, size, inst.Src)
					asm.Mov.Reg(asm.R1, asm.RFP),
					asm.Add.Imm(asm.R1, int32(BpfReadKernelOffset)),
					asm.Mov.Imm(asm.R2, int32(inst.OpCode.Size().Sizeof())),
					asm.Mov.Reg(asm.R3, inst.Src),
					asm.Add.Imm(asm.R3, int32(inst.Offset)),
					asm.FnProbeReadKernel.Call(),

					// inst.Dst = *(RFP-8)
					asm.LoadMem(inst.Dst, asm.RFP, int16(BpfReadKernelOffset), inst.OpCode.Size()),

					// Restore R4, R5 from stack. This is needed because bpf_probe_read_kernel always resets R4 and R5 even if they are not used by bpf_probe_read_kernel.
					asm.LoadMem(asm.R4, asm.RFP, int16(R4Offset), asm.DWord),
					asm.LoadMem(asm.R5, asm.RFP, int16(R5Offset), asm.DWord),
				)

				// Restore R1, R2, R3 from stack
				restoreInsts := asm.Instructions{
					asm.LoadMem(asm.R1, asm.RFP, int16(R1Offset), asm.DWord),
					asm.LoadMem(asm.R2, asm.RFP, int16(R2Offset), asm.DWord),
					asm.LoadMem(asm.R3, asm.RFP, int16(R3Offset), asm.DWord),
				}

				switch inst.Dst {
				case asm.R1, asm.R2, asm.R3:
					restoreInsts = append(restoreInsts[:inst.Dst-1], restoreInsts[inst.Dst:]...)
				}

				replaceInsts[idx] = append(replaceInsts[idx], restoreInsts...)

				// Metadata is crucial for adjusting jump offsets. We
				// ditched original instructions, which could hold symbol
				// names targeted by other jump instructions, so here we
				// inherit the metadata from the ditched ones.
				replaceInsts[idx][0].Metadata = inst.Metadata
			}
		}

		// Replace the memory load instructions with the new ones
		for i := len(replaceIdx) - 1; i >= 0; i-- {
			idx := replaceIdx[i]
			insts = append(insts[:idx], append(replaceInsts[idx], insts[idx+1:]...)...)
		}

		// Store R4, R5 on stack.
		insts = append([]asm.Instruction{
			asm.StoreMem(asm.RFP, int16(R4Offset), asm.R4, asm.DWord),
			asm.StoreMem(asm.RFP, int16(R5Offset), asm.R5, asm.DWord),
		}, insts...)
	}

	return append(insts,
		asm.Mov.Imm(asm.R1, 0).WithSymbol(opts.resultLabel()), // r1 = 0 (_skb)
		asm.Mov.Imm(asm.R2, 0),                                // r2 = 0 (__skb)
		asm.Mov.Imm(asm.R3, 0),                                // r3 = 0 (___skb)
		asm.Mov.Reg(asm.R4, opts.result()),                    // r4 = $result (data)
		asm.Mov.Imm(asm.R5, 0),                                // r5 = 0 (data_end)
	), nil
}
