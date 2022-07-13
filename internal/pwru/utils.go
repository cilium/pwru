// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

type Funcs map[string]int

func GetFuncs(pattern string, spec *btf.Spec, kmods []string) (Funcs, error) {
	funcs := Funcs{}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	iters := []*btf.TypesIterator{spec.Iterate()}
	for _, module := range kmods {
		path := filepath.Join("/sys/kernel/btf", module)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", path, err)
		}
		defer f.Close()

		modSpec, err := btf.LoadSplitSpecFromReader(f, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s btf: %v", module, err)
		}
		iters = append(iters, modSpec.Iterate())
	}

	for _, iter := range iters {
		for iter.Next() {
			typ := iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := string(fn.Name)

			if pattern != "" && reg.FindString(fnName) != fnName {
				continue
			}

			fnProto := fn.Type.(*btf.FuncProto)
			i := 1
			for _, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" && i <= 5 {
							funcs[fnName] = i
							continue
						}
					}
				}
				i += 1
			}
		}
	}

	return funcs, nil
}

func getKernelConfig() (io.Reader, error) {
	//CONFIG_X86_KERNEL_IBT
	var unameBuf unix.Utsname
	if err := unix.Uname(&unameBuf); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/boot/config-%s", unameBuf.Release)
	f, err := os.Open(path)
	if err == nil {
		return gzip.NewReader(f)
	}

	f, err = os.Open("/proc/config.gz")
	if err != nil {
		return nil, err
	}
	return gzip.NewReader(f)
}

var (
	once         sync.Once
	isIBTEnabled bool
)

func adjustAddr(addr uint64) uint64 {
	once.Do(func() {
		r, err := getKernelConfig()
		if err != nil {
			return
		}
		// TODO close
		//defer r.Close()

		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			text := scanner.Text()
			if strings.HasPrefix(text, "CONFIG_X86_KERNEL_IBT=y") {
				isIBTEnabled = true
				return
			}
		}
	})

	// XXX: not sure why the -1 offset is needed on x86 but not on arm64
	if runtime.GOARCH == "amd64" {
		if isIBTEnabled {
			return addr - 5
		}
		return addr - 1
	}

	return addr
}
