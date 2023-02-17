// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package pwru

import (
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/cilium/pwru/internal/byteorder"
)

// Version is the pwru version and is set at compile time via LDFLAGS-
var Version string = "version unknown"

type FilterCfg struct {
	FilterNetns uint32
	FilterMark  uint32

	// Filter l3
	FilterIPv6  uint8
	FilterSrcIP [16]byte
	FilterDstIP [16]byte

	// Filter l4
	FilterProto   uint8
	FilterSrcPort uint16
	FilterDstPort uint16
	FilterPort    uint16

	// TODO: if there are more options later, then you can consider using a bit map
	OutputRelativeTS uint8
	OutputMeta       uint8
	OutputTuple      uint8
	OutputSkb        uint8
	OutputStack      uint8

	IsSet byte
}

func GetConfig(flags *Flags) FilterCfg {
	cfg := FilterCfg{
		FilterNetns: flags.FilterNetns,
		FilterMark:  flags.FilterMark,
		IsSet:       1,
	}
	if flags.FilterPort > 0 {
		cfg.FilterPort = byteorder.HostToNetwork16(flags.FilterPort)
	} else {
		if flags.FilterSrcPort > 0 {
			cfg.FilterSrcPort = byteorder.HostToNetwork16(flags.FilterSrcPort)
		}
		if flags.FilterDstPort > 0 {
			cfg.FilterDstPort = byteorder.HostToNetwork16(flags.FilterDstPort)
		}
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
	if flags.OutputStack {
		cfg.OutputStack = 1
	}

	switch strings.ToLower(flags.FilterProto) {
	case "tcp":
		cfg.FilterProto = syscall.IPPROTO_TCP
	case "udp":
		cfg.FilterProto = syscall.IPPROTO_UDP
	case "icmp":
		cfg.FilterProto = syscall.IPPROTO_ICMP
	case "icmp6":
		cfg.FilterProto = syscall.IPPROTO_ICMPV6
		cfg.FilterIPv6 = 1
	}

	versionMatch := true

	if flags.FilterDstIP != "" {
		ip := net.ParseIP(flags.FilterDstIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-dst-ip")
		}

		if ip.To4() == nil { // ipv6
			cfg.FilterIPv6 = 1
			copy(cfg.FilterDstIP[:], ip.To16()[:])
		} else { // ipv4
			if cfg.FilterIPv6 == 1 {
				versionMatch = false
			}
			copy(cfg.FilterDstIP[:], ip.To4()[:])
		}
	}

	if flags.FilterSrcIP != "" {
		ip := net.ParseIP(flags.FilterSrcIP)
		if ip == nil {
			log.Fatalf("Failed to parse --filter-src-ip")
		}

		if ip.To4() == nil { // ipv6
			if flags.FilterDstIP != "" && cfg.FilterIPv6 == 0 {
				versionMatch = false
			}

			cfg.FilterIPv6 = 1
			copy(cfg.FilterSrcIP[:], ip.To16()[:])
		} else { // ipv4
			if cfg.FilterIPv6 == 1 {
				versionMatch = false
			}
			copy(cfg.FilterSrcIP[:], ip.To4()[:])
		}

		if !versionMatch {
			log.Fatalf("filter-src-ip, filter-dst-ip and filter-proto  should have same version.")
		}
	}

	return cfg
}
