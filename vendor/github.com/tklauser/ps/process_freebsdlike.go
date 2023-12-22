// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build dragonfly || freebsd
// +build dragonfly freebsd

package ps

import (
	"bytes"
	"time"

	"golang.org/x/sys/unix"
)

func (kp *kinfoProc) CreationTime() time.Time {
	return time.Unix(kp.Start.Sec, int64(kp.Start.Usec)*1000)
}

func getExePathAndArgs(pid int) (string, []string) {
	procArgs, err := unix.SysctlRaw("kern.proc.args", pid)
	if err != nil {
		return "", nil
	}
	return parseProcArgs(procArgs)
}

func parseProcArgs(procArgs []byte) (string, []string) {
	if len(procArgs) == 0 {
		return "", nil
	}
	if procArgs[len(procArgs)-1] == 0 {
		procArgs = procArgs[:len(procArgs)-1]
	}
	procArgsSlice := bytes.Split(procArgs, []byte{0})
	args := make([]string, 0, len(procArgsSlice))
	for _, pa := range procArgsSlice {
		args = append(args, string(pa))
	}
	return args[0], args
}

func sysctlProcAll() ([]byte, error) {
	return unix.SysctlRaw("kern.proc.all")
}

func sysctlProcPID(pid int) ([]byte, error) {
	return unix.SysctlRaw("kern.proc.pid", pid)
}
