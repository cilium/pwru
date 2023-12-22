// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ps

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type kinfoProc struct {
	Paddr       uint64
	Flags       int32
	Stat        uint32
	Lock        int32
	Acflag      int32
	Traceflag   int32
	Fd          uint64
	Siglist     sigset_t
	Sigignore   sigset_t
	Sigcatch    sigset_t
	Sigflag     int32
	Start       unix.Timeval
	Comm        [17]byte
	Uid         uint32
	Ngroups     int16
	Groups      [16]uint32
	Ruid        uint32
	Svuid       uint32
	Rgid        uint32
	Svgid       uint32
	Pid         int32
	Ppid        int32
	Pgid        int32
	Jobc        int32
	Sid         int32
	Login       [40]byte
	Tdev        uint32
	Tpgid       int32
	Tsid        int32
	Exitstat    uint16
	Nthreads    int32
	Nice        int32
	Swtime      uint32
	Vm_map_size uint64
	Vm_rssize   int64
	Vm_swrss    int64
	Vm_tsize    int64
	Vm_dsize    int64
	Vm_ssize    int64
	Vm_prssize  uint32
	Jailid      int32
	Ru          unix.Rusage
	Cru         unix.Rusage
	Auxflags    int32
	Lwp         kinfoLwp
	Ktaddr      uint64
	Spare       [2]int32
}

const sizeofKinfoProc = int(unsafe.Sizeof(kinfoProc{}))

type kinfoLwp struct {
	Pid     int32
	Tid     int32
	Flags   int32
	Stat    uint32
	Lock    int32
	Tdflags int32
	Mpcount int32
	Prio    int32
	Tdprio  int32
	Rtprio  rtprio
	Uticks  uint64
	Sticks  uint64
	Iticks  uint64
	Cpticks uint64
	Pctcpu  uint32
	Slptime uint32
	Origcpu int32
	Estcpu  int32
	Cpuid   int32
	Ru      unix.Rusage
	Siglist sigset_t
	Sigmask sigset_t
	Wchan   uint64
	Wmesg   [9]int8
	Comm    [17]int8
	_       [6]byte
}

type rtprio struct {
	Type uint16
	Prio uint16
}

type sigset_t struct {
	Val [4]uint32
}
