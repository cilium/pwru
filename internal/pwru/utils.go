// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"fmt"
	"regexp"

	"github.com/cilium/ebpf/btf"
)

type Funcs map[string]int

func GetFuncs(pattern string, spec *btf.Spec) (Funcs, error) {
	funcs := Funcs{}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	iter := spec.Iterate()
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

	return funcs, nil
}
