// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

type BpfProgName2Addr map[string]uint64

func listBpfProgs(typ ebpf.ProgramType) ([]*ebpf.Program, error) {
	var (
		id  ebpf.ProgramID
		err error
	)

	var progs []*ebpf.Program
	for id, err = ebpf.ProgramGetNextID(id); err == nil; id, err = ebpf.ProgramGetNextID(id) {
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			return nil, err
		}

		if prog.Type() == typ {
			progs = append(progs, prog)
		} else {
			_ = prog.Close()
		}
	}

	if !errors.Is(err, unix.ENOENT) { // Surely err != nil
		return nil, err
	}

	return progs, nil
}

func getEntryFuncName(prog *ebpf.Program) (string, string, error) {
	info, err := prog.Info()
	if err != nil {
		return "", "", fmt.Errorf("failed to get program info: %w", err)
	}

	id, ok := info.BTFID()
	if !ok {
		return "", "", fmt.Errorf("bpf program %s does not have BTF", info.Name)
	}

	handle, err := btf.NewHandleFromID(id)
	if err != nil {
		return "", "", fmt.Errorf("failed to get BTF handle: %w", err)
	}
	defer handle.Close()

	spec, err := handle.Spec(nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to get BTF spec: %w", err)
	}

	iter := spec.Iterate()
	for iter.Next() {
		if fn, ok := iter.Type.(*btf.Func); ok {
			return fn.Name, info.Name, nil
		}
	}

	return "", "", fmt.Errorf("no function found in %s bpf prog", info.Name)
}
