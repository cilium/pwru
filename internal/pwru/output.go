// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/ebpf"
	ps "github.com/mitchellh/go-ps"
)

type output struct {
	flags         *Flags
	lastSeenSkb   map[uint64]uint64 // skb addr => last seen TS
	printSkbMap   *ebpf.Map
	printStackMap *ebpf.Map
	addr2name     Addr2Name
}

func NewOutput(flags *Flags, printSkbMap *ebpf.Map, printStackMap *ebpf.Map, addr2Name Addr2Name) *output {
	return &output{
		flags:         flags,
		lastSeenSkb:   map[uint64]uint64{},
		printSkbMap:   printSkbMap,
		printStackMap: printStackMap,
		addr2name:     addr2Name,
	}
}

func (o *output) PrintHeader() {
	fmt.Printf("%18s %16s %24s %8s %16s\n", "SKB", "PROCESS", "FUNC", "CPU", "TIMESTAMP")
}

func (o *output) Print(event *Event) {
	p, err := ps.FindProcess(int(event.PID))
	execName := "<empty>"
	if err == nil && p != nil {
		execName = p.Executable()
	}
	ts := event.Timestamp
	if o.flags.OutputRelativeTS {
		if last, found := o.lastSeenSkb[event.SAddr]; found {
			ts = ts - last
		} else {
			ts = 0
		}
	}
	fmt.Printf("%18s %16s %24s %8d %16d", fmt.Sprintf("0x%x", event.SAddr), fmt.Sprintf("[%s]", execName), o.addr2name.Addr2NameMap[event.Addr-1].name, event.CPU, ts)
	o.lastSeenSkb[event.SAddr] = event.Timestamp

	if o.flags.OutputMeta {
		fmt.Printf(" netns=%d mark=0x%x pkt_type=%s ifindex=%d proto=%x mtu=%d len=%d", event.Meta.Netns, event.Meta.Mark, pktTypeToStr(event.Meta.PktType), event.Meta.Ifindex, event.Meta.Proto, event.Meta.MTU, event.Meta.Len)
	}

	if o.flags.OutputTuple {
		fmt.Printf(" %s:%d->%s:%d(%s)",
			addrToStr(event.Tuple.L3Proto, event.Tuple.Saddr), byteorder.NetworkToHost16(event.Tuple.Sport),
			addrToStr(event.Tuple.L3Proto, event.Tuple.Daddr), byteorder.NetworkToHost16(event.Tuple.Dport),
			protoToStr(event.Tuple.L4Proto))
	}

	if o.flags.OutputStack && event.PrintStackId > 0 {
		var stack StackData
		id := uint32(event.PrintStackId)
		if err := o.printStackMap.Lookup(&id, &stack); err == nil {
			for _, ip := range stack.IPs {
				if ip > 0 {
					fmt.Printf("\n%s", o.addr2name.findNearestSym(ip))
				}
			}
		}
		_ = o.printStackMap.Delete(&id)
	}

	if o.flags.OutputSkb {
		id := uint32(event.PrintSkbId)
		if str, err := o.printSkbMap.LookupBytes(&id); err == nil {
			fmt.Printf("\n%s", string(str))
		}
	}

	fmt.Println()
}

func protoToStr(proto uint8) string {
	switch proto {
	case syscall.IPPROTO_TCP:
		return "tcp"
	case syscall.IPPROTO_UDP:
		return "udp"
	case syscall.IPPROTO_ICMP:
		return "icmp"
	case syscall.IPPROTO_ICMPV6:
		return "icmp6"
	default:
		return ""
	}
}

func addrToStr(proto uint16, addr [16]byte) string {
	switch proto {
	case syscall.ETH_P_IP:
		return net.IP(addr[:4]).String()
	case syscall.ETH_P_IPV6:
		return fmt.Sprintf("[%s]", net.IP(addr[:]).String())
	default:
		return ""
	}
}

func pktTypeToStr(pktType uint8) string {
	// See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_packet.h#L26
	const (
		PACKET_USER   = 6
		PACKET_KERNEL = 7
	)
	pktTypes := map[uint8]string{
		syscall.PACKET_HOST:      "HOST",
		syscall.PACKET_BROADCAST: "BROADCAST",
		syscall.PACKET_MULTICAST: "MULTICAST",
		syscall.PACKET_OTHERHOST: "OTHERHOST",
		syscall.PACKET_OUTGOING:  "OUTGOING",
		syscall.PACKET_LOOPBACK:  "LOOPBACK",
		PACKET_USER:              "USER",
		PACKET_KERNEL:            "KERNEL",
	}
	if s, ok := pktTypes[pktType]; ok {
		return s
	}
	return ""
}
