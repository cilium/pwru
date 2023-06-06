// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

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
