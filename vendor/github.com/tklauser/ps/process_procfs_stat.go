// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || netbsd
// +build linux netbsd

package ps

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func newUnixProcess(pid int) (Process, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))

	var st unix.Stat_t
	if err := unix.Lstat(procDir, &st); err == unix.ENOENT {
		return nil, fmt.Errorf("no process found with PID %d: %w", pid, err)
	} else if err != nil {
		return nil, fmt.Errorf("failed to lstat %s: %w", procDir, err)
	}
	b, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return nil, err
	}

	// see proc(5) section on /proc/[pid]/stat for the description of the
	// format
	commStart := bytes.IndexByte(b, '(')
	commEnd := bytes.LastIndexByte(b[commStart:], ')') + commStart
	pidS := b[:bytes.IndexByte(b, ' ')]
	comm := b[commStart+1 : commEnd]
	fields := append([][]byte{pidS, comm}, bytes.Fields(b[commEnd+2:])...) // +2 for '( '

	p := &unixProcess{
		pid:          pid,
		uid:          int(st.Uid),
		gid:          int(st.Gid),
		creationTime: time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
	}

	p.ppid, err = strconv.Atoi(string(fields[3]))
	if err != nil {
		return nil, err
	}
	p.command = string(comm)
	p.executablePath, _ = filepath.EvalSymlinks(filepath.Join(procDir, "exe"))

	b, err = os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err == nil && len(b) > 0 {
		p.executableArgs = strings.FieldsFunc(string(b), func(r rune) bool {
			return r == '\u0000'
		})
	}
	return p, nil
}
