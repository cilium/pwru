// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

package pwru

import (
	"fmt"
	"github.com/cilium/ebpf/pkg/btf"
	"regexp"
)

type Funcs map[string]int

func GetFuncs(pattern string) (Funcs, error) {
	funcs := Funcs{}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}
	callback := func(typ btf.Type) {
		fn := typ.(*btf.Func)

		if pattern != "" && !reg.Match([]byte(fn.Name)) {
			return
		}

		fnProto := fn.Type.(*btf.FuncProto)
		i := 1
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == "sk_buff" && i <= 5 {
						funcs[string(fn.Name)] = i
						return
					}
				}
			}
			i += 1
		}
	}
	fn := &btf.Func{}
	spec.Iterate(callback, fn)

	return funcs, nil
}
