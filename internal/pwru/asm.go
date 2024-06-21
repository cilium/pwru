package pwru

import (
	"strings"

	"github.com/cilium/pwru/internal/asm/x86"
)

func GetBpfHelpers(addr2name Addr2Name) (helpers []string, err error) {
	total := len(addr2name.Addr2NameSlice)
	for idx, ksym := range addr2name.Addr2NameSlice {
		if strings.HasSuffix(ksym.name, "[bpf]") {
			leng := 0
			if idx < total-1 {
				leng = int(addr2name.Addr2NameSlice[idx+1].addr - ksym.addr)
			}
			callees, err := x86.GetCallees(ksym.addr, leng)
			if err != nil {
				return nil, err
			}
			for _, calleeAddr := range callees {
				if name, ok := addr2name.Addr2NameMap[calleeAddr]; ok {
					helpers = append(helpers, name.name)
				}
			}
		}
	}
	return
}
