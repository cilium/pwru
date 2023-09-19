package libpcap

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

func InjectFilter(program *ebpf.ProgramSpec, filterExpr string) (err error) {
	if filterExpr == "" {
		return
	}

	injectIdx := -1
	for idx, inst := range program.Instructions {
		if inst.Symbol() == "filter_pcap_ebpf" {
			injectIdx = idx
			break
		}
	}
	if injectIdx == -1 {
		return errors.New("Cannot find the injection position")
	}

	filterEbpf, err := CompileEbpf(filterExpr, cbpfc.EBPFOpts{
		// The rejection position is in the beginning of the `filter_pcap_ebpf` function:
		// filter_pcap_ebpf(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
		// So we can confidently say, skb->data is at r4, skb->data_end is at r5.
		PacketStart: asm.R4,
		PacketEnd:   asm.R5,
		Result:      asm.R0,
		ResultLabel: "result",
		// R0-R3 are also safe to use thanks to the placeholder parameters _skb, __skb, ___skb.
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "filter",
		StackOffset: -int(AvailableOffset),
	})
	if err != nil {
		return
	}

	filterEbpf[0] = filterEbpf[0].WithMetadata(program.Instructions[injectIdx].Metadata)
	program.Instructions[injectIdx] = program.Instructions[injectIdx].WithMetadata(asm.Metadata{})
	program.Instructions = append(program.Instructions[:injectIdx],
		append(filterEbpf, program.Instructions[injectIdx:]...)...,
	)

	return nil
}
