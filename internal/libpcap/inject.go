package libpcap

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
)

func InjectL2TunnelFilter(program *ebpf.ProgramSpec, filterExpr, l2TunnelFilterExpr string) (err error) {
	return injectFilter(program, filterExpr, false, true)
}

func InjectL2Filter(program *ebpf.ProgramSpec, filterExpr string) (err error) {
	return injectFilter(program, filterExpr, false, false)
}

func InjectFilters(program *ebpf.ProgramSpec, filterExpr, tunnelFilterExprL2, tunnelFilterExprL3 string) (err error) {
	if err = injectFilter(program, filterExpr, false, false); err != nil {
		return
	}
	if err = injectFilter(program, filterExpr, true, false); err != nil {
		// This could happen for l2 only filters such as "arp". In this
		// case we don't want to exit with an error, but instead inject
		// a deny-all filter to reject all l3 skbs.
		return injectFilter(program, "__pwru_reject_all__", true, false)
	}
	// Attach any tunnel filters.
	if err := injectFilter(program, tunnelFilterExprL2, false, true); err != nil {
		return fmt.Errorf("l2 tunnel filter: %w", err)
	}
	if err := injectFilter(program, tunnelFilterExprL3, true, true); err != nil {
		return fmt.Errorf("l3 tunnel filter: %w", err)
	}
	return nil
}

func injectFilter(program *ebpf.ProgramSpec, filterExpr string, l3 bool, tunnel bool) (err error) {
	if filterExpr == "" {
		return
	}

	tunnelSuffix := ""
	if tunnel {
		tunnelSuffix = "_tunnel"
	}

	suffix := tunnelSuffix + "_l2"
	if l3 {
		suffix = tunnelSuffix + "_l3"
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

	var filterEbpf asm.Instructions
	if filterExpr == "__pwru_reject_all__" {
		// let data = data_end, so kprobe_pwru.c:filter_pcap_ebpf_l3() always returns false
		filterEbpf = asm.Instructions{
			asm.Mov.Reg(asm.R4, asm.R5), // r4 = r5 (data = data_end)
		}
	} else {
		filterEbpf, err = CompileEbpf(filterExpr, cbpfc.EBPFOpts{
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
	}
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
