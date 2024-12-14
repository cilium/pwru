// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */

package pwru

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

type tracing struct {
	sync.Mutex
	links []link.Link
	progs []*ebpf.Program
}

func (t *tracing) HaveTracing() bool {
	t.Lock()
	defer t.Unlock()

	return len(t.links) > 0
}

func (t *tracing) Detach() {
	t.Lock()
	defer t.Unlock()

	t.detach()

	for _, p := range t.progs {
		_ = p.Close()
	}
	t.progs = nil
}

func (t *tracing) detach() {
	var errg errgroup.Group

	for _, l := range t.links {
		l := l
		errg.Go(func() error {
			_ = l.Close()
			return nil
		})
	}

	_ = errg.Wait()
}

func (t *tracing) addLink(l link.Link) {
	t.Lock()
	defer t.Unlock()

	t.links = append(t.links, l)
}

func (t *tracing) traceProg(spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, prog *ebpf.Program, tracingName string,
) error {
	entryFn, err := getBpfProgInfo(prog)
	if err != nil {
		if errors.Is(err, errNotFound) {
			log.Printf("Skip tracing bpf prog %s because cannot find its entry function name", prog)
			return nil
		}
		return fmt.Errorf("failed to get entry function name: %w", err)
	}

	spec = spec.Copy()
	spec.Programs[tracingName].AttachTarget = prog
	spec.Programs[tracingName].AttachTo = entryFn
	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		return fmt.Errorf("failed to load objects: %s\n%w", verifierLog, err)
	}
	defer coll.Close()

	tracing, err := link.AttachTracing(link.TracingOptions{
		Program: coll.Programs[tracingName],
	})
	if err != nil {
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	t.addLink(tracing)

	return nil
}

func (t *tracing) trace(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, progs []*ebpf.Program, tracingName string,
) error {
	if len(progs) == 0 {
		return nil
	}

	if runtime.GOARCH == "amd64" {
		haveEndbr, err := haveEndbrInsn(progs[0])
		if err != nil {
			return fmt.Errorf("failed to check if the program has ENDBR instruction: %w", err)
		}

		endbrInsnSize := uint32(0)
		if haveEndbr {
			endbrInsnSize = 4
		}
		if err := spec.Variables["ENDBR_INSN_SIZE"].Set(endbrInsnSize); err != nil {
			return fmt.Errorf("failed to set ENDBR_INSN_SIZE: %w", err)
		}
	}

	// Reusing maps from previous collection is to handle the events together
	// with the kprobes.
	replacedMaps := maps.Clone(coll.Maps)
	delete(replacedMaps, ".rodata")
	opts.MapReplacements = replacedMaps

	var errg errgroup.Group

	for _, prog := range progs {
		prog := prog
		errg.Go(func() error {
			return t.traceProg(spec, opts, prog, tracingName)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Detach()
		return fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return nil
}

func TraceTC(coll *ebpf.Collection, spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions) *tracing {
	log.Printf("Attaching tc-bpf progs...\n")

	progs, err := listBpfProgs(ebpf.SchedCLS)
	if err != nil {
		log.Fatalf("failed to list tc-bpf progs: %v", err)
	}

	var t tracing
	t.progs = progs
	t.links = make([]link.Link, 0, len(progs))

	if err := t.trace(coll, spec, opts, progs, "fentry_tc"); err != nil {
		log.Fatalf("failed to trace TC progs: %v", err)
	}

	return &t
}

func TraceXDP(coll *ebpf.Collection, spec *ebpf.CollectionSpec, opts *ebpf.CollectionOptions) *tracing {
	log.Printf("Attaching xdp progs...\n")

	progs, err := listBpfProgs(ebpf.XDP)
	if err != nil {
		log.Fatalf("failed to list XDP progs: %v", err)
	}

	var t tracing
	t.progs = progs
	t.links = make([]link.Link, 0, len(progs)*2)

	{
		spec := spec.Copy()
		delete(spec.Programs, "fexit_xdp")
		if err := t.trace(coll, spec, opts, progs, "fentry_xdp"); err != nil {
			log.Fatalf("failed to trace XDP progs: %v", err)
		}
	}

	{
		spec := spec.Copy()
		delete(spec.Programs, "fentry_xdp")
		if err := t.trace(coll, spec, opts, progs, "fexit_xdp"); err != nil {
			log.Fatalf("failed to trace XDP progs: %v", err)
		}
	}

	return &t
}
