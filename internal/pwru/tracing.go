// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */

package pwru

import (
	"errors"
	"fmt"
	"log"
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
	entryFn, name, err := getEntryFuncName(prog)
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

	addr, ok := n2a[entryFn]
	if !ok {
		addr, ok = n2a[name]
		if !ok {
			return fmt.Errorf("failed to find address for function %s of bpf prog %v", name, prog)
		}
	}

	spec = spec.Copy()
	if err := spec.RewriteConstants(map[string]any{
		"BPF_PROG_ADDR": addr,
	}); err != nil {
		return fmt.Errorf("failed to rewrite bpf prog addr: %w", err)
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
	n2a BpfProgName2Addr, progType ebpf.ProgramType, tracingName string,
) error {
	progs, err := listBpfProgs(progType)
	if err != nil {
		return fmt.Errorf("failed to list bpf progs: %w", err)
	}

	// Reusing maps from previous collection is to handle the events together
	// with the kprobes.
	replacedMaps := map[string]*ebpf.Map{
		"events":          coll.Maps["events"],
		"print_stack_map": coll.Maps["print_stack_map"],
	}
	if outputSkb {
		replacedMaps["print_skb_map"] = coll.Maps["print_skb_map"]
	}
	if outputShinfo {
		replacedMaps["print_shinfo_map"] = coll.Maps["print_shinfo_map"]
	}
	opts.MapReplacements = replacedMaps

	t.links = make([]link.Link, 0, len(progs))
	t.progs = progs

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

	var t tracing
	if err := t.trace(coll, spec, opts, outputSkb, outputShinfo, n2a, ebpf.SchedCLS, "fentry_tc"); err != nil {
		log.Fatalf("failed to trace TC progs: %v", err)
	}

	return &t
}

func TraceXDP(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb bool, outputShinfo bool,
	n2a BpfProgName2Addr,
) *tracing {
	log.Printf("Attaching xdp progs...\n")

	var t tracing
	if err := t.trace(coll, spec, opts, outputSkb, outputShinfo, n2a, ebpf.XDP, "fentry_xdp"); err != nil {
		log.Fatalf("failed to trace XDP progs: %v", err)
	}
	if err := t.trace(coll, spec, opts, outputSkb, outputShinfo, n2a, ebpf.XDP, "fexit_xdp"); err != nil {
		log.Fatalf("failed to trace XDP progs: %v", err)
	}

	return &t
}
