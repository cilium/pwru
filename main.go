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

	pb "github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
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
	if len(funcs) <= 0 {
		log.Fatalf("Cannot find a matching kernel function")
	}
	// If --filter-trace-tc, it's to retrieve and print bpf prog's name.
	addr2name, name2addr, err := pwru.ParseKallsyms(funcs, flags.OutputStack ||
		len(flags.KMods) != 0 || flags.FilterTraceTc || len(flags.FilterNonSkbFuncs) > 0)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100

	var bpfSpec *ebpf.CollectionSpec
	switch {
	case flags.OutputSkb && useKprobeMulti:
		bpfSpec, err = LoadKProbeMultiPWRU()
	case flags.OutputSkb:
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
	if flags.FilterTraceTc && !haveFexit {
		log.Fatalf("Current kernel does not support fentry/fexit to run with --filter-trace-tc")
	}

	// As we know, for every fentry tracing program, there is a corresponding
	// bpf prog spec with attaching target and attaching function. So, we can
	// just copy the spec and keep the fentry_tc program spec only in the copied
	// spec.
	var bpfSpecFentry *ebpf.CollectionSpec
	if flags.FilterTraceTc {
		bpfSpecFentry = bpfSpec.Copy()
		bpfSpecFentry.Programs = map[string]*ebpf.ProgramSpec{
			"fentry_tc": bpfSpec.Programs["fentry_tc"],
		}
	}

	// fentry_tc is not used in the kprobe/kprobe-multi cases. So, it should be
	// deleted from the spec.
	delete(bpfSpec.Programs, "fentry_tc")

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

	if flags.FilterTraceTc {
		close := pwru.TraceTC(coll, bpfSpecFentry, &opts, flags.OutputSkb, name2addr)
		defer close()
	}

	var kprobes []link.Link
	defer func() {
		batch := uint(0)
		if !useKprobeMulti {
			batch = flags.FilterKprobeBatch
		}
		pwru.DetachKprobes(kprobes, batch)
	}()

	msg := "kprobe"
	if useKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching kprobes (via %s)...\n", msg)
	ignored := 0
	bar := pb.StartNew(len(funcs))

	if flags.FilterTrackSkb || flags.FilterTrackSkbByStackid {
		kp, err := link.Kprobe("kfree_skbmem", coll.Programs["kprobe_skb_lifetime_termination"], nil)
		bar.Increment()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Fatalf("Opening kprobe kfree_skbmem: %s\n", err)
			} else {
				ignored += 1
				log.Printf("Warn: kfree_skbmem not found, pwru is likely to mismatch skb due to lack of skb lifetime management\n")
			}
		} else {
			kprobes = append(kprobes, kp)
		}
	}

	if haveFexit && flags.FilterTrackSkb {
		progs := []*ebpf.Program{
			coll.Programs["fexit_skb_clone"],
			coll.Programs["fexit_skb_copy"],
		}
		for _, prog := range progs {
			fexit, err := link.AttachTracing(link.TracingOptions{
				Program: prog,
			})
			bar.Increment()
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					log.Fatalf("Opening tracing(%s): %s\n", prog, err)
				} else {
					ignored += 1
				}
			} else {
				kprobes = append(kprobes, fexit)
			}
		}
	}

	if len(flags.FilterNonSkbFuncs) > 0 {
		for _, fn := range flags.FilterNonSkbFuncs {
			if _, ok := funcs[fn]; ok {
				continue
			}
			kp, err := link.Kprobe(fn, coll.Programs["kprobe_skb_by_stackid"], nil)
			bar.Increment()
			if err != nil {
				log.Fatalf("Opening kprobe %s: %s\n", fn, err)
			}
			kprobes = append(kprobes, kp)
		}
	}

	pwruKprobes := make([]pwru.Kprobe, 0, len(funcs))
	funcsByPos := pwru.GetFuncsByPos(funcs)
	for pos, fns := range funcsByPos {
		fn, ok := coll.Programs[fmt.Sprintf("kprobe_skb_%d", pos)]
		if ok {
			pwruKprobes = append(pwruKprobes, pwru.Kprobe{HookFuncs: fns, Prog: fn})
		} else {
			ignored += len(fns)
			bar.Add(len(fns))
		}
	}
	if !useKprobeMulti {
		l, i := pwru.AttachKprobes(ctx, bar, pwruKprobes, flags.FilterKprobeBatch)
		kprobes = append(kprobes, l...)
		ignored += i
	} else {
		l, i := pwru.AttachKprobeMulti(ctx, bar, pwruKprobes, addr2name)
		kprobes = append(kprobes, l...)
		ignored += i
	}
	bar.Finish()
	select {
	case <-ctx.Done():
		return
	default:
	}
	log.Printf("Attached (ignored %d)\n", ignored)

	log.Println("Listening for events..")

	if flags.ReadyFile != "" {
		file, err := os.Create(flags.ReadyFile)
		if err != nil {
			log.Fatalf("Failed to create ready file: %s", err)
		}
		file.Close()
	}

	printSkbMap := coll.Maps["print_skb_map"]
	printStackMap := coll.Maps["print_stack_map"]
	output, err := pwru.NewOutput(&flags, printSkbMap, printStackMap, addr2name, useKprobeMulti, btfSpec)
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
