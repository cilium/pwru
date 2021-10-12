// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"log"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/ebpf"
)

func ConfigBPFMap(flags *Flags, cfgMap *ebpf.Map) {
	if *flags.FilterMark != 0 {
		key := uint32(CFG_FILTER_KEY_MARK)
		val := uint32(*flags.FilterMark)
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set mark filter %d: %w", *flags.FilterMark, err)
		}
	}

	if *flags.FilterProto != "" {
		proto := 0
		switch strings.ToLower(*flags.FilterProto) {
		case "tcp":
			proto = syscall.IPPROTO_TCP
		case "udp":
			proto = syscall.IPPROTO_UDP
		case "icmp":
			proto = syscall.IPPROTO_ICMP
		}
		if proto != 0 {
			key := uint32(CFG_FILTER_KEY_PROTO)
			val := uint32(proto)
			if err := cfgMap.Update(key, val, 0); err != nil {
				log.Fatalf("Failed to set proto filter %s: %w", *flags.FilterProto, err)
			}
		}
	}

	if *flags.FilterDstIP != "" {
		ip := net.ParseIP(*flags.FilterDstIP)
		val := byteorder.NetIPv4ToHost32(ip)
		key := uint32(CFG_FILTER_KEY_DST_IP)
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set dst ip filter %s: %w", *flags.FilterDstIP, err)
		}
	}

	if *flags.FilterSrcIP != "" {
		ip := net.ParseIP(*flags.FilterSrcIP)
		val := byteorder.NetIPv4ToHost32(ip)
		key := uint32(CFG_FILTER_KEY_SRC_IP)
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set src ip filter %s: %w", *flags.FilterSrcIP, err)
		}
	}

	if *flags.FilterSrcPort != "" {
		port, err := strconv.ParseUint(*flags.FilterSrcPort, 0, 16)
		if err != nil {
			log.Fatalf("Failed to parse src port %s: %w", *flags.FilterSrcPort, err)
		}
		key := uint32(CFG_FILTER_KEY_SRC_PORT)
		val := uint32(byteorder.HostToNetwork16(uint16(port)))
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set src port filter %s: %w", *flags.FilterSrcPort, err)
		}
	}

	if *flags.FilterDstPort != "" {
		port, err := strconv.ParseUint(*flags.FilterDstPort, 0, 16)
		if err != nil {
			log.Fatalf("Failed to parse dst port %s: %w", *flags.FilterDstPort, err)

		}
		key := uint32(CFG_FILTER_KEY_DST_PORT)
		val := uint32(byteorder.HostToNetwork16(uint16(port)))
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set dst port filter %w: %w", *flags.FilterDstPort, err)
		}
	}

	if *flags.OutputMeta {
		key := uint32(CFG_OUTPUT_META)
		val := uint32(1)
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set output meta: %w", err)
		}
	}

	if *flags.OutputTuple {
		key := uint32(CFG_OUTPUT_TUPLE)
		val := uint32(1)
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set output tuple: %w", err)
		}
	}

	if *flags.OutputSkb {
		key := uint32(CFG_OUTPUT_SKB)
		val := uint32(1)
		if err := cfgMap.Update(key, val, 0); err != nil {
			log.Fatalf("Failed to set output skb: %w", err)
		}
	}
}
