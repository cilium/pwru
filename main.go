// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
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

	if flags.Debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if flags.ShowHelp {
		flags.PrintHelp()
		os.Exit(0)
	}
	if flags.ShowVersion {
		fmt.Printf("pwru %s\n", pwru.Version)
		os.Exit(0)
	}

	if err := run(flags); err != nil {
		slog.Error("Failed to run pwru", "error", err)
		os.Exit(1)
	}
}

func run(flags pwru.Flags) error {
	if flags.FilterTrackBpfHelpers {
		if runtime.GOARCH != "amd64" {
			return errors.New("BPF helpers tracking is only supported on amd64")
		}
	}

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		return fmt.Errorf("failed to set temporary RLIMIT_NOFILE: %w", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to set temporary RLIMIT_MEMLOCK: %w", err)
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
		return fmt.Errorf("Failed to load BTF spec: %w", err)
	}

	if (flags.OutputSkb || flags.OutputShinfo) && !pwru.HaveSnprintfBtf(btfSpec) {
		return errors.New("Unsupported to output skb or shinfo because bpf_snprintf_btf() is unavailable")
	}

	if flags.AllKMods {
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			return fmt.Errorf("Failed to read directory: %w", err)
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
		return fmt.Errorf("Invalid tracing backend: %s", flags.Backend)
	}
	// Until https://lore.kernel.org/bpf/20221025134148.3300700-1-jolsa@kernel.org/
	// has been backported to the stable, kprobe-multi cannot be used when attaching
	// to kmods.
	if flags.Backend == "" {
		useKprobeMulti = pwru.HaveBPFLinkKprobeMulti() && pwru.HaveAvailableFilterFunctions()
	} else if flags.Backend == pwru.BackendKprobeMulti {
		useKprobeMulti = true
	}

	funcs, bpfmapFuncs, err := pwru.GetFuncs(flags.FilterFunc, btfSpec, flags.KMods, useKprobeMulti, flags.OutputBpfmap)
	if err != nil {
		return fmt.Errorf("Failed to get skb-accepting functions: %w", err)
	}
	if len(funcs) == 0 && !flags.FilterTraceTc && !flags.FilterTraceXdp {
		return errors.New("Cannot find a matching kernel function")
	}
	// If --filter-trace-tc/--filter-trace-xdp, it's to retrieve and print bpf
	// prog's name.
	addr2name, err := pwru.ParseKallsyms(funcs, flags.OutputStack ||
		len(flags.KMods) != 0 || flags.FilterTraceTc || flags.FilterTraceXdp ||
		len(flags.FilterNonSkbFuncs) > 0 || flags.OutputCaller || flags.FilterTrackBpfHelpers)
	if err != nil {
		return fmt.Errorf("Failed to get function addrs: %w", err)
	}

	bpfSpec, err := LoadKProbePWRU()
	if err != nil {
		return fmt.Errorf("Failed to load bpf spec: %w", err)
	}

	// we delete the program specs that are not needed according to the chosen mode: kprobe vs kprobe-multi
	if useKprobeMulti {
		for i := 1; i <= 5; i++ {
			delete(bpfSpec.Programs, fmt.Sprintf("kprobe_skb_%d", i))
		}
	} else {
		for i := 1; i <= 5; i++ {
			delete(bpfSpec.Programs, fmt.Sprintf("kprobe_multi_skb_%d", i))
		}
	}

	// --output-skb-metadata
	skbMds, err := pwru.ParseSkbMetadataExprs(flags.OutputSkbMetadata, btfSpec)
	if err != nil {
		return fmt.Errorf("Failed to parse skb metadata exprs: %w", err)
	}

	// --output-xdp-metadata
	xdpMds, err := pwru.ParseXdpMetadataExprs(flags.OutputXdpMetadata, btfSpec)
	if err != nil {
		return fmt.Errorf("Failed to parse xdp metadata exprs: %w", err)
	}

	for name, program := range bpfSpec.Programs {
		// Skip the skb-tracking ones that should not inject pcap-filter.
		switch name {
		case "kprobe_skb_lifetime_termination",
			"fexit_skb_clone",
			"fexit_skb_copy",
			"kprobe_veth_convert_skb_to_xdp_buff",
			"kretprobe_veth_convert_skb_to_xdp_buff",
			"fexit_xdp",
			"kretprobe_bpf_map_lookup_elem":
			continue
		case "fentry_xdp":
			if err := libpcap.InjectL2Filter(program, flags.FilterPcap); err != nil {
				return fmt.Errorf("Failed to inject filter ebpf for %s: %w", name, err)
			}
			if err := pwru.InjectFilterXdpExpr(program, btfSpec, flags.FilterXdpExpr); err != nil {
				return fmt.Errorf("Failed to inject filter xdp expr for %s: %w", name, err)
			}
			if err := pwru.InjectSetXdpMetadata(program, xdpMds); err != nil {
				return fmt.Errorf("Failed to inject xdp metadata for %s: %w", name, err)
			}
			continue
		}
		if err = libpcap.InjectFilters(program,
			flags.FilterPcap,
			flags.FilterTunnelPcapL2,
			flags.FilterTunnelPcapL3); err != nil {
			return fmt.Errorf("Failed to inject filter ebpf for %s: %w", name, err)
		}
		if err := pwru.InjectFilterSkbExpr(program, btfSpec, flags.FilterSkbExpr); err != nil {
			return fmt.Errorf("Failed to inject filter skb expr for %s: %w", name, err)
		}
		if err := pwru.InjectSetSkbMetadata(program, skbMds); err != nil {
			return fmt.Errorf("Failed to inject skb metadata for %s: %w", name, err)
		}
	}

	skbBtfID, err := pwru.GetStructBtfID(btfSpec, "sk_buff")
	if err != nil {
		return fmt.Errorf("Failed to get BTF ID for sk_buff: %w", err)
	}
	shinfoBtfID, err := pwru.GetStructBtfID(btfSpec, "skb_shared_info")
	if err != nil {
		return fmt.Errorf("Failed to get BTF ID for skb_shared_info: %w", err)
	}

	pwruConfig, err := pwru.GetConfig(&flags)
	pwruConfig.SkbBtfID = uint32(skbBtfID)
	pwruConfig.ShinfoBtfID = uint32(shinfoBtfID)
	if err != nil {
		return fmt.Errorf("Failed to get pwru config: %w", err)
	}
	if err := bpfSpec.Variables["CFG"].Set(pwruConfig); err != nil {
		return fmt.Errorf("Failed to rewrite config: %w", err)
	}

	bpfSpec.Maps["percpu_big_buff"].ValueSize = flags.SetPerCPUBuf

	haveFexit := pwru.HaveBPFLinkTracing()
	if (flags.FilterTraceTc || flags.FilterTraceXdp) && !haveFexit {
		return errors.New("Current kernel does not support fentry/fexit to run with --filter-trace-tc/--filter-trace-xdp")
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
			"fexit_xdp":  bpfSpecFentryXdp.Programs["fexit_xdp"],
		}
	}

	// fentry_tc&fentry_xdp are not used in the kprobe/kprobe-multi cases. So,
	// they should be deleted from the spec.
	delete(bpfSpec.Programs, "fentry_tc")
	delete(bpfSpec.Programs, "fentry_xdp")
	delete(bpfSpec.Programs, "fexit_xdp")

	// If not tracking skb, deleting the skb-tracking programs to reduce loading
	// time.
	if !flags.FilterTrackSkb && !flags.FilterTrackSkbByStackid {
		delete(bpfSpec.Programs, "kprobe_skb_lifetime_termination")
	}

	if (!flags.FilterTrackSkb && !flags.FilterTrackSkbByStackid) || !haveFexit {
		delete(bpfSpec.Programs, "fexit_skb_clone")
		delete(bpfSpec.Programs, "fexit_skb_copy")
	}

	if !flags.OutputBpfmap {
		delete(bpfSpec.Programs, "kprobe_bpf_map_update_elem")
		delete(bpfSpec.Programs, "kprobe_bpf_map_delete_elem")
		delete(bpfSpec.Programs, "kprobe_bpf_map_lookup_elem")
		delete(bpfSpec.Programs, "kretprobe_bpf_map_lookup_elem")
	}

	if !flags.FilterTrackSkb {
		delete(bpfSpec.Programs, "kprobe_veth_convert_skb_to_xdp_buff")
		delete(bpfSpec.Programs, "kretprobe_veth_convert_skb_to_xdp_buff")
		delete(bpfSpec.Programs, "kprobe_skb_by_stackid")
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	coll, err := ebpf.NewCollectionWithOptions(bpfSpec, opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		if verifierLog != "" {
			return fmt.Errorf("Failed to load objects: %s: %w", verifierLog, err)
		}
		return fmt.Errorf("Failed to load objects: %w", err)
	}
	defer coll.Close()

	traceTc := false
	if flags.FilterTraceTc {
		t, err := pwru.TraceTC(coll, bpfSpecFentryTc, &opts)
		if err != nil {
			return fmt.Errorf("failed to trace TC progs: %w", err)
		}
		defer t.Detach()
		traceTc = t.HaveTracing()
	}

	traceXdp := false
	if flags.FilterTraceXdp {
		t, err := pwru.TraceXDP(coll, bpfSpecFentryXdp, &opts)
		if err != nil {
			return fmt.Errorf("failed to trace XDP progs: %w", err)
		}
		defer t.Detach()
		traceXdp = t.HaveTracing()
	}

	if !traceTc && !traceXdp && len(funcs) == 0 {
		return errors.New("No kprobe/tc-bpf/xdp to trace!")
	}

	if flags.FilterTrackSkb || flags.FilterTrackSkbByStackid {
		t, err := pwru.TrackSkb(coll, haveFexit, flags.FilterTrackSkb)
		if err != nil {
			return fmt.Errorf("Failed to track skb: %w", err)
		}
		defer t.Detach()
	}

	if flags.FilterTrackBpfHelpers {
		bpfHelpers, err := pwru.GetBpfHelpers(addr2name)
		if err != nil {
			return fmt.Errorf("Failed to get bpf helpers: %w", err)
		}
		flags.FilterNonSkbFuncs = append(flags.FilterNonSkbFuncs, bpfHelpers...)
	}

	if nonSkbFuncs := flags.FilterNonSkbFuncs; len(nonSkbFuncs) != 0 {
		k := pwru.NewNonSkbFuncsKprober(nonSkbFuncs, funcs, bpfmapFuncs, coll)
		defer k.DetachKprobes()
	}

	if len(funcs) != 0 {
		k, err := pwru.NewKprober(ctx, funcs, coll, addr2name, useKprobeMulti, flags.FilterKprobeBatch)
		if err != nil {
			return fmt.Errorf("Failed to attach kprobes: %w", err)
		}
		defer k.DetachKprobes()
	}

	slog.Info("Listening for events..")

	if flags.ReadyFile != "" {
		file, err := os.Create(flags.ReadyFile)
		if err != nil {
			return fmt.Errorf("Failed to create ready file: %w", err)
		}
		file.Close()
	}

	printSkbMap := coll.Maps["print_skb_map"]
	printShinfoMap := coll.Maps["print_shinfo_map"]
	printStackMap := coll.Maps["print_stack_map"]
	printBpfmapMap := coll.Maps["print_bpfmap_map"]
	output, err := pwru.NewOutput(&flags, printSkbMap, printShinfoMap, printStackMap, printBpfmapMap, addr2name, skbMds, xdpMds, useKprobeMulti, btfSpec)
	if err != nil {
		return fmt.Errorf("Failed to create outputer: %w", err)
	}
	defer output.Close()

	if !flags.OutputJson {
		output.PrintHeader()
	}

	defer func() {
		select {
		case <-ctx.Done():
			slog.Info("Received signal, exiting program..")
		default:
			slog.Info("Printed events, exiting program..", "count", flags.OutputLimitLines)
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
				return nil
			case <-time.After(time.Microsecond):
				continue
			}
		}

		if flags.OutputJson {
			if err := output.PrintJson(&event); err != nil {
				return fmt.Errorf("Error encoding JSON: %w", err)
			}
		} else {
			output.Print(&event)
		}

		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
	return nil
}
