// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/cilium/pwru/internal/libpcap"
	"github.com/cilium/pwru/internal/pwru"
)

func main() {
	flags := pwru.Flags{}
	flags.SetFlags()
	flags.Parse()

	if flags.ShowHelp {
		flags.PrintHelp()
		os.Exit(0)
	}
	if flags.ShowVersion {
		fmt.Printf("pwru %s\n", pwru.Version)
		os.Exit(0)
	}

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var btfSpec *btf.Spec
	var err error
	if flags.KernelBTF != "" {
		btfSpec, err = btf.LoadSpec(flags.KernelBTF)
	} else {
		btfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	if flags.AllKMods {
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			log.Fatalf("Failed to read directory: %s", err)
		}

		flags.KMods = nil
		for _, file := range files {
			if !file.IsDir() && file.Name() != "vmlinux" {
				flags.KMods = append(flags.KMods, file.Name())
			}
		}
	}

	var useKprobeMulti bool
	if flags.Backend != "" && (flags.Backend != pwru.BackendKprobe && flags.Backend != pwru.BackendKprobeMulti) {
		log.Fatalf("Invalid tracing backend %s", flags.Backend)
	}
	// Until https://lore.kernel.org/bpf/20221025134148.3300700-1-jolsa@kernel.org/
	// has been backported to the stable, kprobe-multi cannot be used when attaching
	// to kmods.
	if flags.Backend == "" && len(flags.KMods) == 0 {
		useKprobeMulti = pwru.HaveBPFLinkKprobeMulti() && pwru.HaveAvailableFilterFunctions()
	} else if flags.Backend == pwru.BackendKprobeMulti {
		useKprobeMulti = true
	}

	funcs, err := pwru.GetFuncs(flags.FilterFunc, btfSpec, flags.KMods, useKprobeMulti)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}
	if len(funcs) == 0 && !flags.FilterTraceTc && !flags.FilterTraceXdp {
		log.Fatalf("Cannot find a matching kernel function")
	}
	// If --filter-trace-tc/--filter-trace-xdp, it's to retrieve and print bpf
	// prog's name.
	addr2name, name2addr, err := pwru.ParseKallsyms(funcs, flags.OutputStack ||
		len(flags.KMods) != 0 || flags.FilterTraceTc || flags.FilterTraceXdp ||
		len(flags.FilterNonSkbFuncs) > 0 || flags.OutputCaller)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100

	var bpfSpec *ebpf.CollectionSpec
	switch {
	case (flags.OutputSkb || flags.OutputShinfo) && useKprobeMulti:
		bpfSpec, err = LoadKProbeMultiPWRU()
	case flags.OutputSkb || flags.OutputShinfo:
		bpfSpec, err = LoadKProbePWRU()
	case useKprobeMulti:
		bpfSpec, err = LoadKProbeMultiPWRUWithoutOutputSKB()
	default:
		bpfSpec, err = LoadKProbePWRUWithoutOutputSKB()
	}
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	for name, program := range bpfSpec.Programs {
		// Skip the skb-tracking ones that should not inject pcap-filter.
		if name == "kprobe_skb_lifetime_termination" ||
			name == "fexit_skb_clone" ||
			name == "fexit_skb_copy" {
			continue
		}
		if name == "fentry_xdp" {
			if err := libpcap.InjectL2Filter(program, flags.FilterPcap); err != nil {
				log.Fatalf("Failed to inject filter ebpf for %s: %v", name, err)
			}
			continue
		}
		if err = libpcap.InjectFilters(program, flags.FilterPcap); err != nil {
			log.Fatalf("Failed to inject filter ebpf for %s: %v", name, err)
		}
	}

	pwruConfig, err := pwru.GetConfig(&flags)
	if err != nil {
		log.Fatalf("Failed to get pwru config: %v", err)
	}
	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": pwruConfig,
	}); err != nil {
		log.Fatalf("Failed to rewrite config: %v", err)
	}

	haveFexit := pwru.HaveBPFLinkTracing()
	if (flags.FilterTraceTc || flags.FilterTraceXdp) && !haveFexit {
		log.Fatalf("Current kernel does not support fentry/fexit to run with --filter-trace-tc/--filter-trace-xdp")
	}

	// As we know, for every fentry tracing program, there is a corresponding
	// bpf prog spec with attaching target and attaching function. So, we can
	// just copy the spec and keep the fentry_tc/fentry_xdp program spec only in
	// the copied spec.
	var bpfSpecFentryTc *ebpf.CollectionSpec
	if flags.FilterTraceTc {
		bpfSpecFentryTc = bpfSpec.Copy()
		bpfSpecFentryTc.Programs = map[string]*ebpf.ProgramSpec{
			"fentry_tc": bpfSpecFentryTc.Programs["fentry_tc"],
		}
	}
	var bpfSpecFentryXdp *ebpf.CollectionSpec
	if flags.FilterTraceXdp {
		bpfSpecFentryXdp = bpfSpec.Copy()
		bpfSpecFentryXdp.Programs = map[string]*ebpf.ProgramSpec{
			"fentry_xdp": bpfSpecFentryXdp.Programs["fentry_xdp"],
		}
	}

	// fentry_tc&fentry_xdp are not used in the kprobe/kprobe-multi cases. So,
	// they should be deleted from the spec.
	delete(bpfSpec.Programs, "fentry_tc")
	delete(bpfSpec.Programs, "fentry_xdp")

	// If not tracking skb, deleting the skb-tracking programs to reduce loading
	// time.
	if !flags.FilterTrackSkb && !flags.FilterTrackSkbByStackid {
		delete(bpfSpec.Programs, "kprobe_skb_lifetime_termination")
	}

	if (!flags.FilterTrackSkb && !flags.FilterTrackSkbByStackid) || !haveFexit {
		delete(bpfSpec.Programs, "fexit_skb_clone")
		delete(bpfSpec.Programs, "fexit_skb_copy")
	}

	coll, err := ebpf.NewCollectionWithOptions(bpfSpec, opts)
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

	traceTc := false
	if flags.FilterTraceTc {
		t := pwru.TraceTC(coll, bpfSpecFentryTc, &opts, flags.OutputSkb, flags.OutputShinfo, name2addr)
		defer t.Detach()
		traceTc = t.HaveTracing()
	}

	traceXdp := false
	if flags.FilterTraceXdp {
		t := pwru.TraceXDP(coll, bpfSpecFentryXdp, &opts, flags.OutputSkb, flags.OutputShinfo, name2addr)
		defer t.Detach()
		traceXdp = t.HaveTracing()
	}

	if !traceTc && !traceXdp && len(funcs) == 0 {
		log.Fatalf("No kprobe/tc-bpf/xdp to trace!")
	}

	if flags.FilterTrackSkb || flags.FilterTrackSkbByStackid {
		t := pwru.TrackSkb(coll, haveFexit, flags.FilterTrackSkb)
		defer t.Detach()
	}

	if nonSkbFuncs := flags.FilterNonSkbFuncs; len(nonSkbFuncs) != 0 {
		k := pwru.KprobeNonSkbFuncs(nonSkbFuncs, funcs, coll)
		defer k.DetachKprobes()
	}

	if len(funcs) != 0 {
		k := pwru.KprobeSkbFuncs(ctx, funcs, coll, addr2name, useKprobeMulti, flags.FilterKprobeBatch)
		defer k.DetachKprobes()
	}

	log.Println("Listening for events..")

	if flags.ReadyFile != "" {
		file, err := os.Create(flags.ReadyFile)
		if err != nil {
			log.Fatalf("Failed to create ready file: %s", err)
		}
		file.Close()
	}

	printSkbMap := coll.Maps["print_skb_map"]
	printShinfoMap := coll.Maps["print_shinfo_map"]
	printStackMap := coll.Maps["print_stack_map"]
	output, err := pwru.NewOutput(&flags, printSkbMap, printShinfoMap, printStackMap, addr2name, useKprobeMulti, btfSpec)
	if err != nil {
		log.Fatalf("Failed to create outputer: %s", err)
	}
	defer output.Close()

	if !flags.OutputJson {
		output.PrintHeader()
	}

	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Received signal, exiting program..")
		default:
			log.Printf("Printed %d events, exiting program..\n", flags.OutputLimitLines)
		}
	}()

	var event pwru.Event
	events := coll.Maps["events"]
	runForever := flags.OutputLimitLines == 0
	for i := flags.OutputLimitLines; i > 0 || runForever; i-- {
		for {
			if err := events.LookupAndDelete(nil, &event); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		if flags.OutputJson {
			output.PrintJson(&event)
		} else {
			output.Print(&event)
		}

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
