package libpcap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"golang.org/x/net/bpf"
)

/*
#cgo CFLAGS: -I${SRCDIR}/../../libpcap
#cgo LDFLAGS: -L${SRCDIR}/../../libpcap -lpcap -static
#include <stdlib.h>
#include <pcap.h>
*/
import "C"

type pcapBpfProgram C.struct_bpf_program

const (
	MaxBpfInstructions       = 4096
	bpfInstructionBufferSize = 8 * MaxBpfInstructions
	MAXIMUM_SNAPLEN          = 262144
)

func CompileCbpf(expr string) (insts []bpf.Instruction, err error) {
	if len(expr) == 0 {
		return
	}

	/*
		DLT_RAW linktype tells pcap_compile() to generate cbpf instructions for
		skb without link layer. This is because kernel doesn't supply L2 data
		for many of functions, where skb->mac_len == 0, while the default
		pcap_compile mode only works for a complete frame data, so we have to
		specify this linktype to tell pcap that the data starts from L3 network
		header.
	*/
	pcap := C.pcap_open_dead(C.DLT_RAW, MAXIMUM_SNAPLEN)
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
Steps:
1. Compile pcap expresion to cbpf using libpcap
2. Convert cbpf to ebpf using cloudflare/cbpfc
3. Convert direct memory load to bpf_probe_read_kernel

The conversion to ebpf requires two registers pointing to the start and
end of the packet data. As we mentioned in the comment of DLT_RAW,
packet data starts from L3 network header, rather than L2 ethernet
header, caller should make sure to pass the correct arguments.
*/
func CompileEbpf(expr string, opts cbpfc.EBPFOpts) (insts asm.Instructions, err error) {
	cbpfInsts, err := CompileCbpf(expr)
	if err != nil {
		return
	}

	ebpfInsts, err := cbpfc.ToEBPF(cbpfInsts, opts)
	if err != nil {
		return
	}

	return adjustEbpf(ebpfInsts, opts)
}

/*
We have to adjust the ebpf instructions because verifier prevents us from
directly loading data from memory. For example, the instruction "r0 = *(u8 *)(r9 +0)"
will break verifier with error "R9 invalid mem access 'scalar", we therefore
need to convert this direct memory load to bpf_probe_read_kernel function call:

- r1 = r10  // r10 is stack top
- r1 += -8  // r1 = r10-8
- r2 = 1    // r2 = sizeof(u8)
- r3 = r9   // r9 is start of packet data, aka L3 header
- r3 += 0   // r3 = r9+0
- call bpf_probe_read_kernel  // *(r10-8) = *(u8 *)(r9+0)
- r0 = *(u8 *)(r10 -8)  // r0 = *(r10-8)

To safely borrow R1, R2 and R3 for setting up the arguments for
bpf_probe_read_kernel(), we need to save the original values of R1, R2 and R3
on stack, and restore them after the function call.

More details in the comments below.
*/
func adjustEbpf(insts asm.Instructions, opts cbpfc.EBPFOpts) (newInsts asm.Instructions, err error) {
	replaceIdx := []int{}
	replaceInsts := map[int]asm.Instructions{}
	for idx, inst := range insts {
		if inst.OpCode.Class().IsLoad() {
			replaceIdx = append(replaceIdx, idx)
			replaceInsts[idx] = append(replaceInsts[idx],

				/*
				   Store R1, R2, R3 on stack. Offsets -16, -24,
				   -32 are used to store R1, R2, R3
				   respectively, we consider these stack area
				   safe to write for now, because:

				   1. bpf_probe_read_kernel uses offset -8 as
				   R1, our choice of -16, -24, and -32 doesn't
				   overlap that;

				   2. [r10-32, r10] stack area has been
				   initialized by "struct event_t event = {}"
				   in the very first of handle_everything(),
				   with nothing set on that so far, so we can
				   borrow this stack temporarily.
				*/
				asm.StoreMem(asm.RFP, -16, asm.R1, asm.DWord),
				asm.StoreMem(asm.RFP, -24, asm.R2, asm.DWord),
				asm.StoreMem(asm.RFP, -32, asm.R3, asm.DWord),

				// bpf_probe_read_kernel(RFP-8, size, inst.Src)
				asm.Mov.Reg(asm.R1, asm.RFP),
				asm.Add.Imm(asm.R1, -8),
				asm.Mov.Imm(asm.R2, int32(inst.OpCode.Size().Sizeof())),
				asm.Mov.Reg(asm.R3, inst.Src),
				asm.Add.Imm(asm.R3, int32(inst.Offset)),
				asm.FnProbeReadKernel.Call(),

				// inst.Dst = *(RFP-8)
				asm.LoadMem(inst.Dst, asm.RFP, -8, inst.OpCode.Size()),
			)

			/*
			 Restore R1, R2, R3 from stack, special handling when
			 inst.Dst is R1, R2 or R3, as we don't want to overwrite
			 its value by mistake.
			*/
			restoreInsts := asm.Instructions{
				asm.LoadMem(asm.R1, asm.RFP, -16, asm.DWord),
				asm.LoadMem(asm.R2, asm.RFP, -24, asm.DWord),
				asm.LoadMem(asm.R3, asm.RFP, -32, asm.DWord),
			}
			switch inst.Dst {
			case asm.R1, asm.R2, asm.R3:
				restoreInsts = append(restoreInsts[:inst.Dst-1], restoreInsts[inst.Dst:]...)
			}
			replaceInsts[idx] = append(replaceInsts[idx], restoreInsts...)

			/*
			 Metadata is crucial for adjusting jump offsets. We
			 ditched original instructions, which could hold symbol
			 names targeted by other jump instructions, so here we
			 inherit the metadata from the ditched ones.
			*/
			replaceInsts[idx][0].Metadata = inst.Metadata
		}
	}

	// Replace the memory load instructions with the new ones
	for i := len(replaceIdx) - 1; i >= 0; i-- {
		idx := replaceIdx[i]
		insts = append(insts[:idx], append(replaceInsts[idx], insts[idx+1:]...)...)
	}

	/*
	 Prepend instructions to init R1, R2, R3 so as to avoid verifier error:
	 permission denied: *(u64 *)(r10 -24) = r2: R2 !read_ok
	*/
	insts = append([]asm.Instruction{
		asm.Mov.Imm(asm.R1, 0),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Imm(asm.R3, 0),
	}, insts...)

	insts = append(insts,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("result"), // r0 = 0
		asm.Mov.Reg(opts.PacketStart, opts.Result),  // skb->data = $result
		asm.Mov.Imm(opts.PacketEnd, 0),              // skb->data_end = 0

	)

	return insts, nil
}
