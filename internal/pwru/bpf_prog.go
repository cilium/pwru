// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Leon Hwang.

package pwru

import (
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

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

	if err != nil && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}

	return progs, nil
}

func getEntryFuncName(prog *ebpf.Program) (string, error) {
	info, err := prog.Info()
	if err != nil {
		return "", fmt.Errorf("failed to get program info: %w", err)
	}

	id, ok := info.BTFID()
	if !ok {
		return "", fmt.Errorf("bpf program %s does not have BTF", info.Name)
	}

	handle, err := btf.NewHandleFromID(id)
	if err != nil {
		return "", fmt.Errorf("failed to get BTF handle: %w", err)
	}
	defer handle.Close()

	spec, err := handle.Spec(nil)
	if err != nil {
		return "", fmt.Errorf("failed to get BTF spec: %w", err)
	}

	iter := spec.Iterate()
	for iter.Next() {
		if fn, ok := iter.Type.(*btf.Func); ok {
			return fn.Name, nil
		}
	}

	return "", fmt.Errorf("no function found in %s bpf prog", info.Name)
}

func TraceTC(prevColl *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb bool,
) (func(), error) {
	progs, err := listBpfProgs(ebpf.SchedCLS)
	if err != nil {
		log.Fatalf("Failed to list TC bpf progs: %v", err)
	}

	// Reusing maps from previous collection is to handle the events together
	// with the kprobes.
	replacedMaps := map[string]*ebpf.Map{
		"events":          prevColl.Maps["events"],
		"print_stack_map": prevColl.Maps["print_stack_map"],
	}
	if outputSkb {
		replacedMaps["print_skb_map"] = prevColl.Maps["print_skb_map"]
	}
	opts.MapReplacements = replacedMaps

	tracings := make([]link.Link, 0, len(progs))
	for _, prog := range progs {
		entryFn, err := getEntryFuncName(prog)
		if err != nil {
			log.Fatalf("Failed to get entry function name: %v", err)
		}
		spec := spec.Copy()
		spec.Programs["fentry_tc"].AttachTarget = prog
		spec.Programs["fentry_tc"].AttachTo = entryFn
		coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
		if err != nil {
			var (
				ve          *ebpf.VerifierError
				verifierLog string
			)
			if errors.As(err, &ve) {
				verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
			}

			log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
		}
		defer coll.Close()

		tracing, err := link.AttachTracing(link.TracingOptions{
			Program: coll.Programs["fentry_tc"],
		})
		if err != nil {
			log.Fatalf("Failed to attach tracing: %v", err)
		}
		tracings = append(tracings, tracing)
	}

	return func() {
		for _, tracing := range tracings {
			_ = tracing.Close()
		}
		for _, prog := range progs {
			_ = prog.Close()
		}
	}, nil
}
