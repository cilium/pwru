// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || netbsd || solaris

package ps

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func processes() ([]Process, error) {
	fd, err := unix.Open("/proc", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc: %w", err)
	}
	f := os.NewFile(uintptr(fd), "proc-dir")
	defer f.Close()

	// Obtain a list of all processes that are currently running.
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	var procs []Process
	for _, name := range names {
		// Filter out non-process entries
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}
		proc, err := newUnixProcess(pid)
		if err != nil {
			continue
		}
		procs = append(procs, proc)
	}
	return procs, nil
}

func findProcess(pid int) (Process, error) {
	return newUnixProcess(pid)
}
