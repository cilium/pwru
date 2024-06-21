package x86

import (
	"debug/elf"
	"fmt"
	"log"
	"os"

	"golang.org/x/arch/x86/x86asm"
)

var (
	kcore    *os.File
	kcoreElf *elf.File
)

func init() {
	var err error
	if kcore, err = os.Open("/proc/kcore"); err != nil {
		log.Fatalf("failed to open /proc/kcore: %s", err)
	}
	if kcoreElf, err = elf.NewFile(kcore); err != nil {
		log.Fatalf("failed to new kcore elf: %s", err)
	}

}

func GetCallees(addr uint64, leng int) (callees []uint64, err error) {
	if leng == 0 {
		leng = 100000
	}
	for _, prog := range kcoreElf.Progs {
		if prog.Vaddr <= addr && prog.Vaddr+prog.Memsz >= addr {
			bytes := make([]byte, leng)
			if _, err = kcore.ReadAt(bytes, int64(prog.Off+addr-prog.Vaddr)); err != nil {
				fmt.Println(err)
			}
			if len(bytes) == 0 {
				continue
			}
			off := 0
			for {
				inst, err := x86asm.Decode(bytes, 64)
				if err != nil {
					inst = x86asm.Inst{Len: 1}
					off += 1
				}
				if inst.Op == x86asm.CALL {
					for _, arg := range inst.Args {
						if arg == nil {
							break
						}
						rel, ok := arg.(x86asm.Rel)
						if !ok {
							break
						}
						callees = append(callees, addr+uint64(off)+uint64(rel)+uint64(inst.Len))
					}
				}
				bytes = bytes[inst.Len:]
				off += inst.Len
				if len(bytes) == 0 {
					break
				}
			}
		}
	}

	return
}
