// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cilium/ebpf/btf"
)

type Funcs map[string]int

// getAvailableFilterFunctions return list of functions to which it is possible
// to attach kprobes.
func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

func GetFuncs(pattern string, spec *btf.Spec, kmods []string) (Funcs, error) {
	funcs := Funcs{}
	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	iters := []iterator{{"", spec.Iterate()}}
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
		iters = append(iters, iterator{module, modSpec.Iterate()})
	}

	for _, it := range iters {
		for it.iter.Next() {
			typ := it.iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := string(fn.Name)

			if pattern != "" && reg.FindString(fnName) != fnName {
				continue
			}

			availableFnName := fnName
			if it.kmod != "" {
				availableFnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
			}
			if _, ok := availableFuncs[availableFnName]; !ok {
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
