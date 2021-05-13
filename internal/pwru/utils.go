package pwru

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/pkg/btf"
)

type Funcs map[string]int

type Addr2Name map[uint64]string

func GetAddrs(funcs Funcs) (Addr2Name, error) {
	a2n := Addr2Name{}

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name := line[2]
		if _, found := funcs[name]; found {
			addr, err := strconv.ParseUint(line[0], 16, 64)
			if err != nil {
				return nil, err
			}
			a2n[addr] = name
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return a2n, nil
}

func GetFuncs() (Funcs, error) {
	funcs := Funcs{}

	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}

	callback := func(typ btf.Type) {
		fn := typ.(*btf.Func)
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
