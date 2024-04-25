// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || netbsd

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

	procStat := filepath.Join(procDir, "stat")
	b, err := os.ReadFile(procStat)
	if err != nil {
		return nil, err
	}

	// see proc(5) section on /proc/[pid]/stat for the description of the
	// format
	commStart := bytes.IndexByte(b, '(')
	commEnd := bytes.LastIndexByte(b[commStart:], ')') + commStart
	comm := string(b[commStart+1 : commEnd])
	fields := bytes.Fields(b[commEnd+2:]) // +2 for '( '
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid process status format in %s", procStat)
	}
	ppid, err := strconv.Atoi(string(fields[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid ppid format %s: %w", fields[1], err)
	}

	p := &unixProcess{
		pid:          pid,
		ppid:         ppid,
		uid:          int(st.Uid),
		gid:          int(st.Gid),
		command:      comm,
		creationTime: time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
	}
	p.executablePath, _ = filepath.EvalSymlinks(filepath.Join(procDir, "exe"))

	b, err = os.ReadFile(filepath.Join(procDir, "cmdline"))
	if err == nil && len(b) > 0 {
		p.executableArgs = strings.FieldsFunc(string(b), func(r rune) bool {
			return r == '\u0000'
		})
	}
	return p, nil
}
