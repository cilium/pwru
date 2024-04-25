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

type tcTracer struct {
	sync.Mutex
	links []link.Link
}

func (t *tcTracer) close() {
	t.Lock()
	defer t.Unlock()

	for _, l := range t.links {
		_ = l.Close()
	}
}

func (t *tcTracer) addLink(l link.Link) {
	t.Lock()
	defer t.Unlock()

	t.links = append(t.links, l)
}

func (t *tcTracer) trace(spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, prog *ebpf.Program, n2a BpfProgName2Addr,
) error {
	entryFn, name, err := getEntryFuncName(prog)
	if err != nil {
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
			return fmt.Errorf("failed to find address for function %s of bpf prog %s", name, prog)
		}
	}

	spec = spec.Copy()
	if err := spec.RewriteConstants(map[string]any{
		"BPF_PROG_ADDR": addr,
	}); err != nil {
		return fmt.Errorf("failed to rewrite bpf prog addr: %w", err)
	}

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

		return fmt.Errorf("failed to load objects: %s\n%w", verifierLog, err)
	}
	defer coll.Close()

	tracing, err := link.AttachTracing(link.TracingOptions{
		Program: coll.Programs["fentry_tc"],
	})
	if err != nil {
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	t.addLink(tracing)

	return nil
}

func TraceTC(coll *ebpf.Collection, spec *ebpf.CollectionSpec,
	opts *ebpf.CollectionOptions, outputSkb bool, outputShinfo bool, n2a BpfProgName2Addr,
) func() {
	progs, err := listBpfProgs(ebpf.SchedCLS)
	if err != nil {
		log.Fatalf("Failed to list TC bpf progs: %v", err)
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

	var tt tcTracer
	tt.links = make([]link.Link, 0, len(progs))

	var errg errgroup.Group

	for _, prog := range progs {
		prog := prog
		errg.Go(func() error {
			return tt.trace(spec, opts, prog, n2a)
		})
	}

	if err := errg.Wait(); err != nil {
		log.Fatalf("Failed to trace TC: %v", err)
	}

	return func() {
		tt.close()

		for _, prog := range progs {
			_ = prog.Close()
		}
	}
}
