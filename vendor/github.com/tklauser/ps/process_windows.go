// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ps

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsProcess struct {
	pid            int
	ppid           int
	command        string
	executablePath string
	executableArgs []string
	creationTime   time.Time
}

func (p *windowsProcess) PID() int {
	return p.pid
}

func (p *windowsProcess) PPID() int {
	return p.ppid
}

func (p *windowsProcess) UID() int {
	return -1
}

func (p *windowsProcess) GID() int {
	return -1
}

func (p *windowsProcess) Command() string {
	return p.command
}

func (p *windowsProcess) ExecutablePath() string {
	if p.executablePath != "" {
		return p.executablePath
	}
	return p.command
}

func (p *windowsProcess) ExecutableArgs() []string {
	return p.executableArgs
}

func (p *windowsProcess) CreationTime() time.Time {
	return p.creationTime
}

func getCreationTime(pid uint32) time.Time {
	c, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return time.Time{}
	}
	defer windows.CloseHandle(c)

	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	if err := windows.GetProcessTimes(c, &creationTime, &exitTime, &kernelTime, &userTime); err != nil {
		return time.Time{}
	}
	return time.Unix(0, creationTime.Nanoseconds())
}

func getExecutablePath(pid uint32) string {
	handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	entry := windows.ModuleEntry32{
		Size: uint32(windows.SizeofModuleEntry32),
	}

	err = windows.Module32First(handle, &entry)
	if err != nil {
		return ""
	}
	return windows.UTF16ToString(entry.ExePath[:])
}

func newWindowsProcess(pe32 *windows.ProcessEntry32) Process {
	return &windowsProcess{
		pid:            int(pe32.ProcessID),
		ppid:           int(pe32.ParentProcessID),
		command:        windows.UTF16ToString(pe32.ExeFile[:]),
		executablePath: getExecutablePath(pe32.ProcessID),
		creationTime:   getCreationTime(pe32.ProcessID),
	}
}

func processes() ([]Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	if err = windows.Process32First(snapshot, &pe32); err != nil {
		return nil, err
	}

	var procs []Process
	for {
		procs = append(procs, newWindowsProcess(&pe32))
		err = windows.Process32Next(snapshot, &pe32)
		if err == windows.ERROR_NO_MORE_FILES {
			break
		} else if err != nil {
			return nil, err
		}
	}
	return procs, nil
}

func findProcess(pid int) (Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	if err = windows.Process32First(snapshot, &pe32); err != nil {
		return nil, err
	}

	for {
		if int(pe32.ProcessID) == pid {
			return newWindowsProcess(&pe32), nil
		}
		err = windows.Process32Next(snapshot, &pe32)
		if err == windows.ERROR_NO_MORE_FILES {
			break
		} else if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("no process found with PID %d", pid)
}
