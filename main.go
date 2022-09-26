// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	flag "github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/pwru/internal/pwru"
)

type Progs map[int]*ebpf.Program

func singleKprobe(funcs pwru.Funcs, progs Progs, ctx context.Context) ([]link.Link, error) {

	var kprobes []link.Link

	log.Println("Attaching single kprobe...")
	ignored := 0
	bar := pb.StartNew(len(funcs))

	for name, pos := range funcs {
		var fn *ebpf.Program
		switch pos {
		case 1:
			fn = progs[1]
		case 2:
			fn = progs[2]
		case 3:
			fn = progs[3]
		case 4:
			fn = progs[4]
		case 5:
			fn = progs[5]
		default:
			ignored += 1
			continue
		}
		select {
		case <-ctx.Done():
			return kprobes, nil
		default:
		}

		kp, err := link.Kprobe(name, fn, nil)
		bar.Increment()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("Opening kprobe %s: %w\n", name, err)
			} else {
				ignored += 1
			}
		} else {
			kprobes = append(kprobes, kp)
		}

	}

	bar.Finish()
	log.Printf("Attached (ignored %d)\n", ignored)

	return kprobes, nil
}

func multiKprobe(funcs pwru.Funcs, progs Progs, ffuncs []string, ctx context.Context) ([]link.Link, error) {

	var kprobes []link.Link
	ksyms := make(map[*ebpf.Program][]string)
	ignored := 0

	for name, pos := range funcs {
		var p *ebpf.Program
		switch pos {
		case 1:
			p = progs[1]
			ksyms[p] = append(ksyms[p], name)
		case 2:
			p = progs[2]
			ksyms[p] = append(ksyms[p], name)
		case 3:
			p = progs[3]
			ksyms[p] = append(ksyms[p], name)
		case 4:
			p = progs[4]
			ksyms[p] = append(ksyms[p], name)
		case 5:
			p = progs[5]
			ksyms[p] = append(ksyms[p], name)
		default:
			ignored += 1
			continue
		}

	}

	log.Println("Attaching multi kprobes...")

	for prog, syms := range ksyms {

		s := interSection(ffuncs, syms)
		opts := link.KprobeMultiOptions{Symbols: s}

		lnk, err := link.KprobeMulti(prog, opts)
		if err != nil {
			return nil, fmt.Errorf("attaching '%s' failed: %w", prog, err)
		} else {
			kprobes = append(kprobes, lnk)
		}

		select {
		case <-ctx.Done():
			return kprobes, nil
		default:
		}

	}

	log.Printf("Attached (ignored %d)\n", ignored)

	return kprobes, nil
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// took from https://go.dev/play/p/eGGcyIlZD6y
func interSection(ffuncs, syms []string) (inter []string) {
	out := []string{}
	bucket := map[string]bool{}
	for _, i := range ffuncs {
		for _, j := range syms {
			if i == j && !bucket[i] {
				out = append(out, i)
				bucket[i] = true
			}
		}
	}
	return out
}

func main() {
	var (
		cfgMap, events, printSkbMap, printStackMap *ebpf.Map
	)

	kProbeSkb := Progs{}
	flags := pwru.Flags{}
	flags.SetFlags()
	flag.Parse()

	if flags.ShowVersion {
		fmt.Printf("pwru %s\n", pwru.Version)
		os.Exit(0)
	}

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 4096,
		Max: 4096,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
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

	funcs, err := pwru.GetFuncs(flags.FilterFunc, btfSpec, flags.KMods)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}
	if len(funcs) <= 0 {
		log.Fatalf("Cannot find a matching kernel function")
	}
	addr2name, err := pwru.GetAddrs(funcs, flags.OutputStack || len(flags.KMods) != 0)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec

	if flags.OutputSkb {
		objs := KProbePWRUObjects{}
		if err := LoadKProbePWRUObjects(&objs, &opts); err != nil {
			log.Fatalf("Loading objects: %v", err)
		}
		defer objs.Close()
		kProbeSkb[1] = objs.KprobeSkb1
		kProbeSkb[2] = objs.KprobeSkb2
		kProbeSkb[3] = objs.KprobeSkb3
		kProbeSkb[4] = objs.KprobeSkb4
		kProbeSkb[5] = objs.KprobeSkb5
		cfgMap = objs.CfgMap
		events = objs.Events
		printSkbMap = objs.PrintSkbMap
		printStackMap = objs.PrintStackMap
	} else {
		objs := KProbePWRUWithoutOutputSKBObjects{}
		if err := LoadKProbePWRUWithoutOutputSKBObjects(&objs, &opts); err != nil {
			log.Fatalf("Loading objects: %v", err)
		}
		defer objs.Close()
		kProbeSkb[1] = objs.KprobeSkb1
		kProbeSkb[2] = objs.KprobeSkb2
		kProbeSkb[3] = objs.KprobeSkb3
		kProbeSkb[4] = objs.KprobeSkb4
		kProbeSkb[5] = objs.KprobeSkb5
		cfgMap = objs.CfgMap
		events = objs.Events
		printStackMap = objs.PrintStackMap
	}

	log.Printf("Per cpu buffer size: %d bytes\n", flags.PerCPUBuffer)
	pwru.ConfigBPFMap(&flags, cfgMap)

	var kprobes []link.Link

	ffuncs, err := readLines("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}

	kprobes, err = multiKprobe(funcs, kProbeSkb, ffuncs, ctx)

	if err != nil {
		log.Printf("Failed to attach multi kprobes: %s", err)
		kprobes, err = singleKprobe(funcs, kProbeSkb, ctx)
		if err != nil {
			log.Fatalf("Failed to attach single kprobe: %s", err)
		}
	}
	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Detaching kprobes...")
			bar := pb.StartNew(len(kprobes))
			for _, kp := range kprobes {
				_ = kp.Close()
				bar.Increment()
			}
			bar.Finish()

		default:
			for _, kp := range kprobes {
				_ = kp.Close()
			}
		}
	}()

	rd, err := perf.NewReader(events, flags.PerCPUBuffer)
	if err != nil {
		log.Fatalf("Creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()

		if err := rd.Close(); err != nil {
			log.Fatalf("Closing perf event reader: %s", err)
		}
	}()

	log.Println("Listening for events..")

	output := pwru.NewOutput(&flags, printSkbMap, printStackMap, addr2name)
	output.PrintHeader()

	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Received signal, exiting program..")
		default:
			log.Printf("Printed %d events, exiting program..\n", flags.OutputLimitLines)
		}
	}()

	var event pwru.Event
	runForever := flags.OutputLimitLines == 0
	for i := flags.OutputLimitLines; i > 0 || runForever; i-- {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %s", err)
		}

		if record.LostSamples != 0 {
			log.Printf("Perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Parsing perf event: %s", err)
			continue
		}

		output.Print(&event)

		select {
		case <-ctx.Done():
			break
		default:
			continue
		}
	}
}
