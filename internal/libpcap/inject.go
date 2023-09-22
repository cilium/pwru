package libpcap

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

func InjectFilters(program *ebpf.ProgramSpec, filterExpr string) (err error) {
	if err = injectFilter(program, filterExpr, false); err != nil {
		return
	}
	if err = injectFilter(program, filterExpr, true); err != nil {
		// This could happen for l2 only filters such as "arp". In this
		// case we don't want to exit with an error, but instead inject
		// a deny-all filter to reject all l3 skbs.
		fmt.Printf("L3 filter injection failed while L2 filter injection succeeded, injecting a deny-all L3 filter: %+v\n", err)
		return injectFilter(program, "src host 0.0.0.0 and dst host 0.0.0.0 and tcp", true)
	}
	return
}

func injectFilter(program *ebpf.ProgramSpec, filterExpr string, l3 bool) (err error) {
	if filterExpr == "" {
		return
	}

	suffix := "_l2"
	if l3 {
		suffix = "_l3"
	}
	injectIdx := -1
	for idx, inst := range program.Instructions {
		if inst.Symbol() == "filter_pcap_ebpf"+suffix {
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
		ResultLabel: "result" + suffix,
		// R0-R3 are also safe to use thanks to the placeholder parameters _skb, __skb, ___skb.
		Working:     [4]asm.Register{asm.R0, asm.R1, asm.R2, asm.R3},
		LabelPrefix: "filter" + suffix,
		StackOffset: -int(AvailableOffset),
	}, l3)
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
