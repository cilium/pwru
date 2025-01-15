// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */

package pwru

import (
	"errors"
	"fmt"
	"log"
	"maps"
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
	opts *ebpf.CollectionOptions, prog *ebpf.Program, n2a BpfProgName2Addr,
	tracingName string,
) error {
	entryFn, progName, tag, err := getBpfProgInfo(prog)
	if err != nil {
		if errors.Is(err, errNotFound) {
			log.Printf("Skip tracing bpf prog %s because cannot find its entry function name", prog)
			return nil
		}
		return fmt.Errorf("failed to get entry function name: %w", err)
	}

	// The addr may hold the wrong rip value, because two addresses could
	// have one same symbol. As discussed before, that doesn't affect the
	// symbol resolution because even a "wrong" rip can be matched to the
	// right symbol. However, this could make a difference when we want to
	// distinguish which exact bpf prog is called.
	//   -- @jschwinger233

	progKsym := fmt.Sprintf("bpf_prog_%s_%s[bpf]", tag, entryFn)
	addr, ok := n2a[progKsym]
	if !ok {
		progKsym = fmt.Sprintf("bpf_prog_%s_%s[bpf]", tag, progName)
		addr, ok = n2a[progKsym]
		if !ok {
			return fmt.Errorf("failed to find address for function %s of bpf prog %v", progName, prog)
		}
	}

	spec = spec.Copy()
	if err := spec.Variables["BPF_PROG_ADDR"].Set(addr); err != nil {
		return fmt.Errorf("failed to set bpf prog addr: %w", err)
	}

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
	opts *ebpf.CollectionOptions, outputSkb bool, outputShinfo bool,
	n2a BpfProgName2Addr, progs []*ebpf.Program, tracingName string,
) error {
	// Reusing maps from previous collection is to handle the events together
	// with the kprobes.
	replacedMaps := maps.Clone(coll.Maps)
	delete(replacedMaps, ".rodata")
	opts.MapReplacements = replacedMaps

	var errg errgroup.Group

	for _, prog := range progs {
		prog := prog
		errg.Go(func() error {
			return t.traceProg(spec, opts, prog, n2a, tracingName)
		})
	}

	if err := errg.Wait(); err != nil {
		t.Detach()
		return fmt.Errorf("failed to trace bpf progs: %w", err)
	}

	return nil
}

func TraceTC(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb bool, outputShinfo bool,
	n2a BpfProgName2Addr,
) *tracing {
	log.Printf("Attaching tc-bpf progs...\n")

	progs, err := listBpfProgs(ebpf.SchedCLS)
	if err != nil {
		log.Fatalf("failed to list tc-bpf progs: %v", err)
	}

	var t tracing
	t.progs = progs
	t.links = make([]link.Link, 0, len(progs))

	if err := t.trace(coll, spec, opts, outputSkb, outputShinfo, n2a, progs, "fentry_tc"); err != nil {
		log.Fatalf("failed to trace TC progs: %v", err)
	}

	return &t
}

func TraceXDP(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb bool, outputShinfo bool,
	n2a BpfProgName2Addr,
) *tracing {
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
		if err := t.trace(coll, spec, opts, outputSkb, outputShinfo, n2a, progs, "fentry_xdp"); err != nil {
			log.Fatalf("failed to trace XDP progs: %v", err)
		}
	}

	{
		spec := spec.Copy()
		delete(spec.Programs, "fentry_xdp")
		if err := t.trace(coll, spec, opts, outputSkb, outputShinfo, n2a, progs, "fexit_xdp"); err != nil {
			log.Fatalf("failed to trace XDP progs: %v", err)
		}
	}

	return &t
}
