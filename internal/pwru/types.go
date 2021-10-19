// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import flag "github.com/spf13/pflag"

const (
	CFG_FILTER_KEY_DEFAULT = 0x0
	CFG_MAX                = 0x1
)

type Flags struct {
	FilterMark    uint32
	FilterProto   string
	FilterSrcIP   string
	FilterDstIP   string
	FilterSrcPort uint16
	FilterDstPort uint16

	OutputRelativeTS bool
	OutputMeta       bool
	OutputTuple      bool
	OutputSkb        bool
}

func (f *Flags) SetFlags() {
	flag.StringVar(&f.FilterProto, "filter-proto", "", "filter L4 protocol (tcp, udp, icmp)")
	flag.StringVar(&f.FilterSrcIP, "filter-src-ip", "", "filter source IP addr")
	flag.StringVar(&f.FilterDstIP, "filter-dst-ip", "", "filter destination IP addr")
	flag.Uint32Var(&f.FilterMark, "filter-mark", 0, "filter skb mark")
	flag.Uint16Var(&f.FilterSrcPort, "filter-src-port", 0, "filter source port")
	flag.Uint16Var(&f.FilterDstPort, "filter-dst-port", 0, "filter destination port")
	flag.BoolVar(&f.OutputRelativeTS, "output-relative-timestamp", false, "print relative timestamp per skb")
	flag.BoolVar(&f.OutputMeta, "output-meta", false, "print skb metadata")
	flag.BoolVar(&f.OutputTuple, "output-tuple", false, "print L4 tuple")
	flag.BoolVar(&f.OutputSkb, "output-skb", false, "print skb")
}

type Tuple struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Proto uint8
	Pad   [7]uint8
}

type Meta struct {
	Mark    uint32
	Ifindex uint32
	Len     uint32
	MTU     uint32
	Proto   uint16
	Pad     uint16
}

type Event struct {
	PID        uint32
	Type       uint32
	Addr       uint64
	SAddr      uint64
	Timestamp  uint64
	PrintSkbId uint64
	Meta       Meta
	Tuple      Tuple
}
