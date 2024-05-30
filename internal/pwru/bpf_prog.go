// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
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

	insns, err := info.Instructions()
	if err != nil {
		return "", "", fmt.Errorf("failed to get program instructions: %w", err)
	}

	for _, insn := range insns {
		sym := insn.Symbol()
		if sym != "" {
			return sym, info.Name, nil
		}
	}

	return "", "", fmt.Errorf("no function found in %s bpf prog", info.Name)
}
