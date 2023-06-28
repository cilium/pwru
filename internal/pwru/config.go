// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package pwru

import (
	"fmt"
	"strings"
)

// Version is the pwru version and is set at compile time via LDFLAGS-
var Version string = "version unknown"

type FilterCfg struct {
	FilterNetns uint32
	FilterMark  uint32

	// TODO: if there are more options later, then you can consider using a bit map
	OutputRelativeTS uint8
	OutputMeta       uint8
	OutputTuple      uint8
	OutputSkb        uint8
	OutputStack      uint8

	IsSet    byte
	TrackSkb byte
}

func GetConfig(flags *Flags) FilterCfg {
	cfg := FilterCfg{
		FilterNetns: flags.FilterNetns,
		FilterMark:  flags.FilterMark,
		IsSet:       1,
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

	if flags.FilterTrackSkb {
		cfg.TrackSkb = 1
	}

	return cfg
}

func GetPcapFilter(flags *Flags) string {
	filters := []string{}
	if flags.FilterPcap != "" {
		filters = append(filters, flags.FilterPcap)
	}

	if flags.FilterProto != "" {
		filters = append(filters, strings.ToLower(flags.FilterProto))
	}

	if flags.FilterSrcIP != "" {
		filters = append(filters, "src host "+flags.FilterSrcIP)
	}

	if flags.FilterDstIP != "" {
		filters = append(filters, "dst host "+flags.FilterDstIP)
	}

	if flags.FilterSrcPort != 0 {
		filters = append(filters, fmt.Sprintf("src port %d", flags.FilterSrcPort))
	}

	if flags.FilterDstPort != 0 {
		filters = append(filters, fmt.Sprintf("dst port %d", flags.FilterDstPort))
	}

	if flags.FilterPort != 0 {
		filters = append(filters, fmt.Sprintf("port %d", flags.FilterPort))
	}

	for i, filter := range filters {
		filters[i] = "(" + filter + ")"
	}
	return strings.Join(filters, " and ")
}
