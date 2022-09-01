// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/cilium/ebpf"
	ps "github.com/mitchellh/go-ps"

	"github.com/cilium/pwru/internal/byteorder"
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
	fmt.Printf("%18s %16s %24s %16s\n", "SKB", "PROCESS", "FUNC", "TIMESTAMP")
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
	var addr uint64
	// XXX: not sure why the -1 offset is needed on x86 but not on arm64
	switch runtime.GOARCH {
	case "amd64":
		addr = event.Addr - 1
	case "arm64":
		addr = event.Addr
	}
	var funcName string
	if ksym, ok := o.addr2name.Addr2NameMap[addr]; ok {
		funcName = ksym.name
	} else if ksym, ok := o.addr2name.Addr2NameMap[addr-4]; runtime.GOARCH == "amd64" && ok {
		// Assume that function has ENDBR in its prelude (enabled by CONFIG_X86_KERNEL_IBT).
		// See https://lore.kernel.org/bpf/20220811091526.172610-5-jolsa@kernel.org/
		// for more ctx.
		funcName = ksym.name
	} else {
		funcName = fmt.Sprintf("0x%x", addr)
	}
	fmt.Printf("%18s %16s %24s %16d", fmt.Sprintf("0x%x", event.SAddr), fmt.Sprintf("[%s]", execName), funcName, ts)
	o.lastSeenSkb[event.SAddr] = event.Timestamp

	if o.flags.OutputMeta {
		fmt.Printf(" netns=%d mark=0x%x ifindex=%d proto=%x mtu=%d len=%d", event.Meta.Netns, event.Meta.Mark, event.Meta.Ifindex, event.Meta.Proto, event.Meta.MTU, event.Meta.Len)
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
