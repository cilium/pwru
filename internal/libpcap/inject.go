package libpcap

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/jschwinger233/elibpcap"
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
		return injectFilter(program, elibpcap.RejectAllExpr, true, false)
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

	program.Instructions, err = elibpcap.Inject(
		filterExpr,
		program.Instructions,
		elibpcap.Options{
			AtBpf2Bpf:  "filter_pcap_ebpf" + suffix,
			DirectRead: false,
			L2Skb:      !l3,
		},
	)
	return

}
