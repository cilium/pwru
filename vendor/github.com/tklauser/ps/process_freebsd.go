// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ps

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// TODO: add this to x/sys/unix
type kinfoProc struct {
	Structsize     int32
	Layout         int32
	Args           uintptr
	Paddr          uintptr
	Addr           uintptr
	Tracep         uintptr
	Textvp         uintptr
	Fd             uintptr
	Vmspace        uintptr
	Wchan          *byte
	Pid            int32
	Ppid           int32
	Pgid           int32
	Tpgid          int32
	Sid            int32
	Tsid           int32
	Jobc           int16
	Spare_short1   int16
	Tdev_freebsd11 uint32
	Siglist        unix.Sigset_t
	Sigmask        unix.Sigset_t
	Sigignore      unix.Sigset_t
	Sigcatch       unix.Sigset_t
	Uid            uint32
	Ruid           uint32
	Svuid          uint32
	Rgid           uint32
	Svgid          uint32
	Ngroups        int16
	Spare_short2   int16
	Groups         [16]uint32
	Size           uint64
	Rssize         int64
	Swrss          int64
	Tsize          int64
	Dsize          int64
	Ssize          int64
	Xstat          uint16
	Acflag         uint16
	Pctcpu         uint32
	Estcpu         uint32
	Slptime        uint32
	Swtime         uint32
	Cow            uint32
	Runtime        uint64
	Start          unix.Timeval
	Childtime      unix.Timeval
	Flag           int64
	Kiflag         int64
	Traceflag      int32
	Stat           int8
	Nice           int8
	Lock           int8
	Rqindex        int8
	Oncpu_old      uint8
	Lastcpu_old    uint8
	Tdname         [17]byte
	Wmesg          [9]byte
	Login          [18]byte
	Lockname       [9]byte
	Comm           [20]byte
	Emul           [17]byte
	Loginclass     [18]byte
	Moretdname     [4]byte
	Sparestrings   [46]byte
	Spareints      [2]int32
	Tdev           uint64
	Oncpu          int32
	Lastcpu        int32
	Tracer         int32
	Flag2          int32
	Fibnum         int32
	Cr_flags       uint32
	Jid            int32
	Numthreads     int32
	Tid            int32
	Pri            priority
	Rusage         unix.Rusage
	Rusage_ch      unix.Rusage
	Pcb            uintptr
	Kstack         *byte
	Udata          *byte
	Tdaddr         uintptr
	Pd             uintptr
	Spareptrs      [5]*byte
	Sparelongs     [12]int64
	Sflag          int64
	Tdflags        int64
}

const sizeofKinfoProc = int(unsafe.Sizeof(kinfoProc{}))

// TODO: add this to x/sys/unix
type priority struct {
	Class  uint8
	Level  uint8
	Native uint8
	User   uint8
}
