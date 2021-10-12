package btf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/pkg"
)

type bpfBTFInfo struct {
	btf       pkg.Pointer
	btfSize   uint32
	id        uint32
	name      pkg.Pointer
	nameLen   uint32
	kernelBTF uint32
}

func bpfGetBTFInfoByFD(fd *pkg.FD, btf, name []byte) (*bpfBTFInfo, error) {
	info := bpfBTFInfo{
		btf:     pkg.NewSlicePointer(btf),
		btfSize: uint32(len(btf)),
		name:    pkg.NewSlicePointer(name),
		nameLen: uint32(len(name)),
	}
	if err := pkg.BPFObjGetInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return nil, fmt.Errorf("can't get program info: %w", err)
	}

	return &info, nil
}
