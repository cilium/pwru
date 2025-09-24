// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var errNotFound = errors.New("not found")

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
			log.Printf("Found bpf prog: %s\n", prog.String())
			progs = append(progs, prog)
		} else {
			_ = prog.Close()
		}
	}

	if !errors.Is(err, unix.ENOENT) { // Surely err != nil
		return nil, err
	}

	if len(progs) == 0 {
		log.Printf("No bpf progs found with type '%s'\n", typ.String())
	}

	return progs, nil
}

func getBpfProgInfo(prog *ebpf.Program) (entryFuncName string, err error) {
	info, err := prog.Info()
	if err != nil {
		err = fmt.Errorf("failed to get program info: %w", err)
		return
	}

	_, ok := info.BTFID()
	if !ok {
		// FENTRY/FEXIT program can only be attached to another program
		// annotated with BTF. So if the BTF ID is not found, it means
		// the program is not annotated with BTF.
		err = errNotFound
		return
	}

	insns, err := info.Instructions()
	if err != nil {
		err = fmt.Errorf("failed to get program instructions: %w", err)
		return
	}

	for _, insn := range insns {
		sym := insn.Symbol()
		if sym != "" {
			return sym, nil
		}
	}

	err = errNotFound
	return
}
