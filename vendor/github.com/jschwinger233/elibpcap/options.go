package elibpcap

import "github.com/cilium/ebpf/asm"

type Options struct {
	// AtBpf2Bpf is the label where the bpf2bpf call is injected.
	// The rejection position requires the function to be declared as:
	//
	//	static __noinline bool
	//	filter_pcap_ebpf(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
	//
	// In this case, AtBpf2Bpf is the name of the function: filter_pcap_ebpf
	AtBpf2Bpf string

	// DirectRead indicates if the injected bpf program should use "direct packet access" or not.
	// See https://docs.kernel.org/bpf/verifier.html#direct-packet-access
	DirectRead bool

	// L2Skb indicates if the injected bpf program should use L2 skb or not.
	// The L2 skb is the one that contains the ethernet header, while the L3 skb->data points to the IP header.
	L2Skb bool
}

func (o Options) resultLabel() string {
	return "_result_" + o.AtBpf2Bpf
}

func (o Options) labelPrefix() string {
	return "_prefix_" + o.AtBpf2Bpf
}

func (o Options) result() asm.Register {
	return asm.R0
}
