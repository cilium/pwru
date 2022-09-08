// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package pwru

import (
	"os"

	flag "github.com/spf13/pflag"
)

const (
	MaxStackDepth = 50
)

type Flags struct {
	ShowVersion bool

	KernelBTF string

	FilterNetns   uint32
	FilterMark    uint32
	FilterFunc    string
	FilterProto   string
	FilterSrcIP   string
	FilterDstIP   string
	FilterSrcPort uint16
	FilterDstPort uint16

	OutputTS         string
	OutputMeta       bool
	OutputTuple      bool
	OutputSkb        bool
	OutputStack      bool
	OutputLimitLines uint64

	PerCPUBuffer int
	KMods        []string
}

func (f *Flags) SetFlags() {
	flag.BoolVar(&f.ShowVersion, "version", false, "show pwru version and exit")
	flag.StringVar(&f.KernelBTF, "kernel-btf", "", "specify kernel BTF file")
	flag.StringSliceVar(&f.KMods, "kmods", nil, "list of kernel modules names to attach to")
	flag.StringVar(&f.FilterFunc, "filter-func", "", "filter kernel functions to be probed by name (exact match, supports RE2 regular expression)")
	flag.StringVar(&f.FilterProto, "filter-proto", "", "filter L4 protocol (tcp, udp, icmp, icmp6)")
	flag.StringVar(&f.FilterSrcIP, "filter-src-ip", "", "filter source IP addr")
	flag.StringVar(&f.FilterDstIP, "filter-dst-ip", "", "filter destination IP addr")
	flag.Uint32Var(&f.FilterNetns, "filter-netns", 0, "filter netns inode")
	flag.Uint32Var(&f.FilterMark, "filter-mark", 0, "filter skb mark")
	flag.Uint16Var(&f.FilterSrcPort, "filter-src-port", 0, "filter source port")
	flag.Uint16Var(&f.FilterDstPort, "filter-dst-port", 0, "filter destination port")
	flag.StringVar(&f.OutputTS, "timestamp", "none", "print timestamp per skb (\"current\", \"relative\", \"none\")")
	flag.BoolVar(&f.OutputMeta, "output-meta", false, "print skb metadata")
	flag.BoolVar(&f.OutputTuple, "output-tuple", false, "print L4 tuple")
	flag.BoolVar(&f.OutputSkb, "output-skb", false, "print skb")
	flag.BoolVar(&f.OutputStack, "output-stack", false, "print stack")
	flag.Uint64Var(&f.OutputLimitLines, "output-limit-lines", 0, "exit the program after the number of events has been received/printed")
	flag.IntVar(&f.PerCPUBuffer, "per-cpu-buffer", os.Getpagesize(), "per CPU buffer in bytes")
}

type Tuple struct {
	Saddr   [16]byte
	Daddr   [16]byte
	Sport   uint16
	Dport   uint16
	L3Proto uint16
	L4Proto uint8
	Pad     uint8
}

type Meta struct {
	Netns   uint32
	Mark    uint32
	Ifindex uint32
	Len     uint32
	MTU     uint32
	Proto   uint16
	Pad     uint16
}

type StackData struct {
	IPs [MaxStackDepth]uint64
}

type Event struct {
	PID          uint32
	Type         uint32
	Addr         uint64
	SAddr        uint64
	Timestamp    uint64
	PrintSkbId   uint64
	Meta         Meta
	Tuple        Tuple
	PrintStackId int64
	CPU          uint32
}
