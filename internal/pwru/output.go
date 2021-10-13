// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/ebpf"
	ps "github.com/mitchellh/go-ps"
)

type output struct {
	flags       *Flags
	lastSeenSkb map[uint64]uint64 // skb addr => last seen TS
	printSkbMap *ebpf.Map
	addr2name   Addr2Name
}

func NewOutput(flags *Flags, printSkbMap *ebpf.Map, addr2Name Addr2Name) *output {
	return &output{
		flags:       flags,
		lastSeenSkb: map[uint64]uint64{},
		printSkbMap: printSkbMap,
		addr2name:   addr2Name,
	}
}

func (o *output) PrintHeader() {
	fmt.Printf("%18s %15s %24s %16s\n", "SKB", "PROCESS", "FUNC", "TIMESTAMP")
}

func (o *output) Print(event *Event) {
	p, err := ps.FindProcess(int(event.PID))
	execName := "<empty>"
	if err == nil && p != nil {
		execName = p.Executable()
	}
	ts := event.Timestamp
	if *o.flags.OutputRelativeTS {
		if last, found := o.lastSeenSkb[event.SAddr]; found {
			ts = ts - last
		} else {
			ts = 0
		}
	}
	fmt.Printf("%18s %15s %24s %16d", fmt.Sprintf("0x%x", event.SAddr), fmt.Sprintf("[%s]", execName), o.addr2name[event.Addr-1], ts)
	o.lastSeenSkb[event.SAddr] = event.Timestamp

	if *o.flags.OutputMeta {
		fmt.Printf(" mark=0x%x ifindex=%d proto=%x mtu=%d len=%d", event.Meta.Mark, event.Meta.Ifindex, event.Meta.Proto, event.Meta.MTU, event.Meta.Len)
	}

	if *o.flags.OutputTuple {
		fmt.Printf(" %s:%d->%s:%d(%s)",
			u32ToNetIPv4(event.Tuple.Saddr), byteorder.NetworkToHost16(event.Tuple.Sport),
			u32ToNetIPv4(event.Tuple.Daddr), byteorder.NetworkToHost16(event.Tuple.Dport),
			protoToStr(event.Tuple.Proto))
	}

	if *o.flags.OutputSkb {
		id := uint32(event.PrintSkbId)
		if event.PrintSkbId != 0 {
			if str, err := o.printSkbMap.LookupBytes(&id); err == nil {
				fmt.Printf("\n%s", string(str))
			}
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
	default:
		return ""
	}
}

func u32ToNetIPv4(in uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, in)
	return ip
}
