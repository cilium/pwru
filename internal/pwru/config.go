// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

import (
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Version is the pwru version and is set at compile time via LDFLAGS-
var Version string = "version unknown"

type FilterCfg struct {
	FilterNetns   uint32
	FilterMark    uint32
	FilterIfindex uint32

	// TODO: if there are more options later, then you can consider using a bit map
	OutputRelativeTS uint8
	OutputMeta       uint8
	OutputTuple      uint8
	OutputSkb        uint8
	OutputStack      uint8

	IsSet    byte
	TrackSkb byte
}

func GetConfig(flags *Flags) (cfg FilterCfg, err error) {
	cfg = FilterCfg{
		FilterMark: flags.FilterMark,
		IsSet:      1,
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

	netnsID, ns, err := parseNetns(flags.FilterNetns)
	if err != nil {
		err = fmt.Errorf("Failed to retrieve netns %s: %w", flags.FilterNetns, err)
		return
	}
	if flags.FilterIfname != "" || flags.FilterNetns != "" {
		cfg.FilterNetns = netnsID
	}
	if cfg.FilterIfindex, err = parseIfindex(flags.FilterIfname, ns); err != nil {
		return
	}
	return
}

func parseNetns(netnsSpecifier string) (netnsID uint32, ns netns.NsHandle, err error) {
	switch {
	case netnsSpecifier == "":
		ns, err = netns.Get()
	case strings.HasPrefix(netnsSpecifier, "/"):
		ns, err = netns.GetFromPath(netnsSpecifier)
	case strings.HasPrefix(netnsSpecifier, "inode:"):
		var netnsInode int
		netnsInode, err = strconv.Atoi(netnsSpecifier[6:])
		netnsID = uint32(netnsInode)
	default:
		err = fmt.Errorf("invalid netns specifier: %s", netnsSpecifier)
	}
	if ns == 0 || err != nil {
		return
	}
	var s unix.Stat_t
	if err = unix.Fstat(int(ns), &s); err != nil {
		return
	}
	return uint32(s.Ino), ns, nil
}

func parseIfindex(ifname string, ns netns.NsHandle) (ifindex uint32, err error) {
	if ifname == "" {
		return
	}
	if ns == 0 {
		return 0, fmt.Errorf("inode netns specifier cannot be used with --filter-ifname")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	currentNetns, err := netns.Get()
	if err != nil {
		return
	}
	defer netns.Set(currentNetns)

	if err = netns.Set(ns); err != nil {
		return
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return
	}
	return uint32(iface.Index), nil
}
