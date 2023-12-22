// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ps

import (
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TODO: add this to x/sys/unix
type kinfoProc struct {
	Forw         uint64
	Back         uint64
	Paddr        uint64
	Addr         uint64
	Fd           uint64
	Stats        uint64
	Limit        uint64
	Vmspace      uint64
	Sigacts      uint64
	Sess         uint64
	Tsess        uint64
	Ru           uint64
	Eflag        int32
	Exitsig      int32
	Flag         int32
	Pid          int32
	Ppid         int32
	Sid          int32
	_            int32
	Tpgid        int32
	Uid          uint32
	Ruid         uint32
	Gid          uint32
	Rgid         uint32
	Groups       [16]uint32
	Ngroups      int16
	Jobc         int16
	Tdev         uint32
	Estcpu       uint32
	Rtime_sec    uint32
	Rtime_usec   uint32
	Cpticks      int32
	Pctcpu       uint32
	Swtime       uint32
	Slptime      uint32
	Schedflags   int32
	Uticks       uint64
	Sticks       uint64
	Iticks       uint64
	Tracep       uint64
	Traceflag    int32
	Holdcnt      int32
	Siglist      int32
	Sigmask      uint32
	Sigignore    uint32
	Sigcatch     uint32
	Stat         int8
	Priority     uint8
	Usrpri       uint8
	Nice         uint8
	Xstat        uint16
	Acflag       uint16
	Comm         [24]byte
	Wmesg        [8]byte
	Wchan        uint64
	Login        [32]byte
	Vm_rssize    int32
	Vm_tsize     int32
	Vm_dsize     int32
	Vm_ssize     int32
	Uvalid       int64
	Ustart_sec   uint64
	Ustart_usec  uint32
	Uutime_sec   uint32
	Uutime_usec  uint32
	Ustime_sec   uint32
	Ustime_usec  uint32
	Uru_maxrss   uint64
	Uru_ixrss    uint64
	Uru_idrss    uint64
	Uru_isrss    uint64
	Uru_minflt   uint64
	Uru_majflt   uint64
	Uru_nswap    uint64
	Uru_inblock  uint64
	Uru_oublock  uint64
	Uru_msgsnd   uint64
	Uru_msgrcv   uint64
	Uru_nsignals uint64
	Uru_nvcsw    uint64
	Uru_nivcsw   uint64
	Uctime_sec   uint32
	Uctime_usec  uint32
	Psflags      uint32
	Spare        int32
	Svuid        uint32
	Svgid        uint32
	Emul         [8]byte
	Rlim_rss_cur uint64
	Cpuid        uint64
	Vm_map_size  uint64
	Tid          int32
	Rtableid     uint32
	Pledge       uint64
}

const sizeofKinfoProc = int(unsafe.Sizeof(kinfoProc{}))

func (kp *kinfoProc) CreationTime() time.Time {
	return time.Unix(int64(kp.Ustart_sec), int64(kp.Ustart_usec)*1000)
}

func getExePathAndArgs(pid int) (string, []string) {
	return "", nil
}

const (
	_KERN_PROC_ALL = 0
	_KERN_PROC_PID = 1
)

func sysctlProcAll() ([]byte, error) {
	return unix.SysctlRaw("kern.proc", _KERN_PROC_ALL, 0, sizeofKinfoProc, 1024)
}

func sysctlProcPID(pid int) ([]byte, error) {
	return unix.SysctlRaw("kern.proc", _KERN_PROC_PID, pid, sizeofKinfoProc, 1)
}
