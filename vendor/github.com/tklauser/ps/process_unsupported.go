// Copyright 2021 Tobias Klauser. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package ps

import (
	"fmt"
	"runtime"
)

func processes() ([]Process, error) {
	return nil, fmt.Errorf("unsupported on %s", runtime.GOOS)
}

func findProcess(pid int) (Process, error) {
	return nil, fmt.Errorf("unsupported on %s", runtime.GOOS)
}
