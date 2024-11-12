// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package pwru

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
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

func GetFuncs(pattern string, spec *btf.Spec, kmods []string, kprobeMulti bool) (Funcs, error) {
	funcs := Funcs{}

	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	var availableFuncs map[string]struct{}
	if kprobeMulti {
		availableFuncs, err = getAvailableFilterFunctions()
		if err != nil {
			log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
		}
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

			if kprobeMulti {
				availableFnName := fnName
				if it.kmod != "" {
					availableFnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
				}
				if _, ok := availableFuncs[availableFnName]; !ok {
					continue
				}
			}

			fnProto := fn.Type.(*btf.FuncProto)
			i := 1
			for _, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == "sk_buff" && i <= 5 {
							name := fnName
							if kprobeMulti && it.kmod != "" {
								name = fmt.Sprintf("%s [%s]", fnName, it.kmod)
							}
							funcs[name] = i
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

func GetFuncsByPos(funcs Funcs) map[int][]string {
	ret := make(map[int][]string, len(funcs))
	for fn, pos := range funcs {
		ret[pos] = append(ret[pos], fn)
	}
	return ret
}

// Very hacky way to check whether multi-link kprobe is supported.
func HaveBPFLinkKprobeMulti() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_kpm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceKprobeMulti,
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	opts := link.KprobeMultiOptions{Symbols: []string{"vprintk"}}
	link, err := link.KretprobeMulti(prog, opts)
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

// Very hacky way to check whether tracing link is supported.
func HaveBPFLinkTracing() bool {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "fexit_skb_clone",
		Type: ebpf.Tracing,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceFExit,
		AttachTo:   "skb_clone",
		License:    "MIT",
	})
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}

func HaveAvailableFilterFunctions() bool {
	_, err := getAvailableFilterFunctions()
	return err == nil
}

func HaveSnprintfBtf(kernelBtf *btf.Spec) bool {
	types, err := kernelBtf.AnyTypesByName("bpf_func_id")
	if err != nil {
		return false
	}

	for _, t := range types {
		if enum, ok := t.(*btf.Enum); ok {
			for _, v := range enum.Values {
				if v.Name == "BPF_FUNC_snprintf_btf" {
					return true
				}
			}
		}
	}

	return false
}
