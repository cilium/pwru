// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ps

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type psinfo struct {
	Flag     int32
	Nlwp     int32
	Pid      int32
	Ppid     int32
	Pgid     int32
	Sid      int32
	Uid      uint32
	Euid     uint32
	Gid      uint32
	Egid     uint32
	Addr     uint64
	Size     uint64
	Rssize   uint64
	Pad1     uint64
	Ttydev   uint64
	Pctcpu   uint16
	Pctmem   uint16
	Start    unix.Timespec
	Time     unix.Timespec
	Ctim     unix.Timespec
	Fname    [16]byte
	Psargs   [80]byte
	Wstat    int32
	Argc     int32
	Argv     uint64
	Envp     uint64
	Dmodel   int8
	Pad2     [3]int8
	Taskid   int32
	Projid   int32
	Nzomb    int32
	Poolid   int32
	Zoneid   int32
	Contract int32
	Filler   [1]int32
	Lwp      lwpsinfo
}

type lwpsinfo struct {
	Flag     int32
	Lwpid    int32
	Addr     uint64
	Wchan    uint64
	Stype    int8
	State    int8
	Sname    int8
	Nice     int8
	Syscall  int16
	Oldpri   int8
	Cpu      int8
	Pri      int32
	Pctcpu   uint16
	Pad      uint16
	Start    unix.Timespec
	Time     unix.Timespec
	Clname   [8]byte
	Name     [16]byte
	Onpro    int32
	Bindpro  int32
	Bindpset int32
	Lgrp     int32
	Filler   [4]int32
}

func newUnixProcess(pid int) (Process, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))

	var st unix.Stat_t
	if err := unix.Lstat(procDir, &st); err == unix.ENOENT {
		return nil, fmt.Errorf("no process found with PID %d: %w", pid, err)
	} else if err != nil {
		return nil, fmt.Errorf("failed to lstat %s: %w", procDir, err)
	}

	f, err := os.Open(filepath.Join(procDir, "psinfo"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var psi psinfo
	err = binary.Read(f, binary.LittleEndian, &psi)
	if err != nil {
		return nil, err
	}

	p := &unixProcess{
		pid:          pid,
		ppid:         int(psi.Ppid),
		uid:          int(st.Uid),
		gid:          int(st.Gid),
		command:      unix.ByteSliceToString(psi.Fname[:]),
		creationTime: time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
	}

	p.executablePath, _ = filepath.EvalSymlinks(filepath.Join(procDir, "path", "a.out"))

	b, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err == nil && len(b) > 0 {
		p.executableArgs = strings.FieldsFunc(string(b), func(r rune) bool {
			return r == '\u0000'
		})
	}

	return p, nil
}
