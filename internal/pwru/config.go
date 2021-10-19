// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/ebpf"
)

type FilterCfg struct {
	FilterMark uint32

	//Filter l3
	FilterIPv6  uint8
	FilterSrcIP [16]byte
	FilterDstIP [16]byte

	//Filter l4
	FilterProto   uint8
	FilterSrcPort uint16
	FilterDstPort uint16

	//TODO: if there are more options later, then you can consider using a bit map
	OutputRelativeTS uint8
	OutputMeta       uint8
	OutputTuple      uint8
	OutputSkb        uint8

	Pad [2]byte
}

func ConfigBPFMap(flags *Flags, cfgMap *ebpf.Map) {
	cfg := FilterCfg{
		FilterMark: flags.FilterMark,
	}

	if flags.FilterSrcPort > 0 {
		cfg.FilterSrcPort = byteorder.HostToNetwork16(flags.FilterSrcPort)
	}
	if flags.FilterDstPort > 0 {
		cfg.FilterDstPort = byteorder.HostToNetwork16(flags.FilterDstPort)
	}
	if flags.OutputSkb {
		cfg.OutputSkb = 1
	}
	if flags.OutputMeta {
		cfg.OutputMeta = 1
	}
	if flags.OutputTuple {
		cfg.OutputTuple = 1
	}

	switch strings.ToLower(flags.FilterProto) {
	case "tcp":
		cfg.FilterProto = syscall.IPPROTO_TCP
	case "udp":
		cfg.FilterProto = syscall.IPPROTO_UDP
	case "icmp":
		cfg.FilterProto = syscall.IPPROTO_ICMP
	}

	if flags.FilterDstIP != "" {
		ip := net.ParseIP(flags.FilterDstIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-dst-ip")
		}
		if ip4 := ip.To4(); ip4 == nil {
			cfg.FilterIPv6 = 1
			copy(cfg.FilterDstIP[:], ip.To16()[:])
		} else {
			copy(cfg.FilterDstIP[:], ip4[:])
		}
	}

	if flags.FilterSrcIP != "" {
		ip := net.ParseIP(flags.FilterSrcIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-src-ip")
		}

		versionMatch := true
		if ip4 := ip.To4(); ip4 == nil {
			if cfg.FilterIPv6 <= 0 && flags.FilterDstIP != "" {
				versionMatch = false
			}
			copy(cfg.FilterSrcIP[:], ip.To16()[:])
		} else {
			if cfg.FilterIPv6 > 0 {
				versionMatch = false
			}
			copy(cfg.FilterSrcIP[:], ip4[:])
		}
		if !versionMatch {
			log.Fatalf("filter-src-ip and filter-dst-ip should have same version.")
		}
	}

	key := uint32(CFG_FILTER_KEY_DEFAULT)
	if err := cfgMap.Update(key, cfg, 0); err != nil {
		log.Fatalf("Failed to set filter map: %w", err)
	}
}
