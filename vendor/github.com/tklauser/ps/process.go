// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ps provides functionality to find, list and inspect operating system
// processes, without using cgo or external binaries.
package ps

import "time"

// Process is the generic interface for common process information.
type Process interface {
	// PID returns the process ID for this process.
	PID() int
	// PPID returns the parent process ID for this process.
	PPID() int
	// UID returns the numeric user ID for this process. On Windows, it
	// always returns -1.
	UID() int
	// GID returns the numeric group ID for this process. On Windows, it
	// always returns -1.
	GID() int
	// ExecutablePath returns the full path to the executable of this
	// process. This information might not be available on all platforms or
	// if the executable was removed while the process was still running.
	ExecutablePath() string
	// ExecutableArgs returns the command line arguments for this process,
	// including the executable name. This information might not be
	// available on all platforms.
	ExecutableArgs() []string
	// Command returns the command or executable name running this process.
	// On some platforms (e.g. macOS and the BSDs) this name might be
	// truncated.
	Command() string
	// CreationTime returns the creation time for this process.
	CreationTime() time.Time
}

// Processes returns all currently running processes.
func Processes() ([]Process, error) {
	return processes()
}

// FindProcess returns the process identified by pid or an error if no process
// with that identifier is found.
func FindProcess(pid int) (Process, error) {
	return findProcess(pid)
}
