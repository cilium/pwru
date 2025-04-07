package pwru

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
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

func injectBpfStub(prog *ebpf.ProgramSpec, stub string, insns asm.Instructions) error {
	startIdx := -1
	for i, ins := range prog.Instructions {
		if ins.Symbol() == stub {
			startIdx = i
			break
		}
	}
	if startIdx == -1 {
		return fmt.Errorf("failed to find stub %s", stub)
	}

	retIdx := -1
	retOpCode := asm.Return().OpCode
	for i := startIdx + 1; i < len(prog.Instructions); i++ {
		if prog.Instructions[i].OpCode == retOpCode {
			retIdx = i
			break
		}
	}
	if retIdx == -1 {
		return fmt.Errorf("failed to find ret instruction of stub %s", stub)
	}

	// replace the stub's instructions
	insns[0] = insns[0].WithMetadata(prog.Instructions[startIdx].Metadata)
	prog.Instructions = append(prog.Instructions[:startIdx],
		append(insns, prog.Instructions[retIdx+1:]...)...)

	return nil
}
