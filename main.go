// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021-2022 Authors of Cilium */

package main

import (
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

func main() {
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
		useKprobeMulti = pwru.HaveBPFLinkKprobeMulti()
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
	addr2name, err := pwru.GetAddrs(funcs, flags.OutputStack || len(flags.KMods) != 0)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec

	var objs pwru.KProbeObjects
	switch {
	case flags.OutputSkb && useKprobeMulti:
		objs = &KProbeMultiPWRUObjects{}
		err = LoadKProbeMultiPWRUObjects(objs, &opts)
	case flags.OutputSkb:
		objs = &KProbePWRUObjects{}
		err = LoadKProbePWRUObjects(objs, &opts)
	case useKprobeMulti:
		objs = &KProbeMultiPWRUWithoutOutputSKBObjects{}
		err = LoadKProbeMultiPWRUWithoutOutputSKBObjects(objs, &opts)
	default:
		objs = &KProbePWRUWithoutOutputSKBObjects{}
		err = LoadKProbePWRUWithoutOutputSKBObjects(objs, &opts)
	}

	if err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	kprobe1 := objs.GetKprobeSkb1()
	kprobe2 := objs.GetKprobeSkb2()
	kprobe3 := objs.GetKprobeSkb3()
	kprobe4 := objs.GetKprobeSkb4()
	kprobe5 := objs.GetKprobeSkb5()

	cfgMap := objs.GetCfgMap()
	events := objs.GetEvents()
	printStackMap := objs.GetPrintStackMap()
	var printSkbMap *ebpf.Map
	if flags.OutputSkb {
		printSkbMap = objs.(pwru.KProbeMapsWithOutputSKB).GetPrintSkbMap()
	}

	log.Printf("Per cpu buffer size: %d bytes\n", flags.PerCPUBuffer)
	pwru.ConfigBPFMap(&flags, cfgMap)

	var kprobes []link.Link
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

	msg := "kprobe"
	if useKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching kprobes (via %s)...\n", msg)
	ignored := 0
	bar := pb.StartNew(len(funcs))
	funcsByPos := pwru.GetFuncsByPos(funcs)
	for pos, fns := range funcsByPos {
		var fn *ebpf.Program
		switch pos {
		case 1:
			fn = kprobe1
		case 2:
			fn = kprobe2
		case 3:
			fn = kprobe3
		case 4:
			fn = kprobe4
		case 5:
			fn = kprobe5
		default:
			ignored += 1
			continue
		}

		if !useKprobeMulti {
			for _, name := range fns {
				select {
				case <-ctx.Done():
					bar.Finish()
					return
				default:
				}

				kp, err := link.Kprobe(name, fn, nil)
				bar.Increment()
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						log.Fatalf("Opening kprobe %s: %s\n", name, err)
					} else {
						ignored += 1
					}
				} else {
					kprobes = append(kprobes, kp)
				}
			}
		} else {
			select {
			case <-ctx.Done():
				bar.Finish()
				return
			default:
			}

			opts := link.KprobeMultiOptions{Symbols: funcsByPos[pos]}
			kp, err := link.KprobeMulti(fn, opts)
			bar.Add(len(fns))
			if err != nil {
				log.Fatalf("Opening kprobe-multi for pos %d: %s\n", pos, err)
			}
			kprobes = append(kprobes, kp)
		}
	}
	bar.Finish()
	log.Printf("Attached (ignored %d)\n", ignored)

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

	if flags.ReadyFile != "" {
		file, err := os.Create(flags.ReadyFile)
		if err != nil {
			log.Fatalf("Failed to create ready file: %s", err)
		}
		file.Close()
	}

	output, err := pwru.NewOutput(&flags, printSkbMap, printStackMap, addr2name, useKprobeMulti)
	if err != nil {
		log.Fatalf("Failed to create outputer: %s", err)
	}
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
			return
		default:
		}
	}
}
