// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ps

import (
	"path/filepath"
	"time"
)

type unixProcess struct {
	pid            int
	ppid           int
	uid            int
	gid            int
	command        string // might be truncated, e.g. on macOS and the BSDs
	executablePath string
	executableArgs []string
	creationTime   time.Time
}

func (p *unixProcess) PID() int {
	return p.pid
}

func (p *unixProcess) PPID() int {
	return p.ppid
}

func (p *unixProcess) UID() int {
	return p.uid
}

func (p *unixProcess) GID() int {
	return p.gid
}

func (p *unixProcess) Command() string {
	if p.executablePath != "" {
		return filepath.Base(p.executablePath)
	}
	return p.command
}

func (p *unixProcess) ExecutablePath() string {
	if p.executablePath != "" {
		return p.executablePath
	}
	return p.command
}

func (p *unixProcess) ExecutableArgs() []string {
	return p.executableArgs
}

func (p *unixProcess) CreationTime() time.Time {
	return p.creationTime
}
