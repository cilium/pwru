// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */

package pwru

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

type kprober struct {
	links []link.Link

	kprobeMulti bool
	kprobeBatch uint
}

type Kprobe struct {
	hookFunc  string // internal use
	HookFuncs []string
	Prog      *ebpf.Program
}

func attachKprobes(ctx context.Context, bar *pb.ProgressBar, kprobes []Kprobe) (links []link.Link, ignored int, err error) {
	links = make([]link.Link, 0, len(kprobes))
	for _, kprobe := range kprobes {
		select {
		case <-ctx.Done():
			return

		default:
		}

		var kp link.Link
		kp, err = link.Kprobe(kprobe.hookFunc, kprobe.Prog, nil)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
				err = fmt.Errorf("opening kprobe %s: %w", kprobe.hookFunc, err)
				return
			} else {
				err = nil
				ignored++
			}
		} else {
			links = append(links, kp)
		}

		bar.Increment()
	}

	return
}

// AttachKprobes attaches kprobes concurrently.
func AttachKprobes(ctx context.Context, bar *pb.ProgressBar, kps []Kprobe, batch uint) (links []link.Link, ignored int) {
	if batch == 0 {
		log.Fatal("--filter-kprobe-batch must be greater than 0")
	}

	var kprobes []Kprobe
	for _, kp := range kps {
		for _, fn := range kp.HookFuncs {
			kprobes = append(kprobes, Kprobe{
				hookFunc: fn,
				Prog:     kp.Prog,
			})
		}
	}

	if len(kprobes) == 0 {
		return
	}

	errg, ctx := errgroup.WithContext(ctx)

	var mu sync.Mutex
	links = make([]link.Link, 0, len(kprobes))

	attaching := func(kprobes []Kprobe) error {
		l, i, e := attachKprobes(ctx, bar, kprobes)
		if e != nil {
			return e
		}

		mu.Lock()
		links = append(links, l...)
		ignored += i
		mu.Unlock()

		return nil
	}

	var i uint
	for i = 0; i+batch < uint(len(kprobes)); i += batch {
		kps := kprobes[i : i+batch]
		errg.Go(func() error {
			return attaching(kps)
		})
	}
	if i < uint(len(kprobes)) {
		kps := kprobes[i:]
		errg.Go(func() error {
			return attaching(kps)
		})
	}

	if err := errg.Wait(); err != nil {
		log.Fatalf("Attaching kprobes: %v\n", err)
	}

	return
}

// DetachKprobes detaches kprobes concurrently.
func (k *kprober) DetachKprobes() {
	log.Println("Detaching kprobes...")

	links := k.links
	bar := pb.StartNew(len(links))
	defer bar.Finish()

	batch := k.kprobeBatch
	if k.kprobeMulti || batch >= uint(len(links)) {
		for _, l := range links {
			_ = l.Close()
			bar.Increment()
		}

		return
	}

	var errg errgroup.Group
	var i uint
	for i = 0; i+batch < uint(len(links)); i += batch {
		l := links[i : i+batch]
		errg.Go(func() error {
			for _, l := range l {
				_ = l.Close()
				bar.Increment()
			}
			return nil
		})
	}
	for ; i < uint(len(links)); i++ {
		_ = links[i].Close()
		bar.Increment()
	}

	_ = errg.Wait()
}

// AttachKprobeMulti attaches kprobe-multi serially.
func AttachKprobeMulti(ctx context.Context, bar *pb.ProgressBar, kprobes []Kprobe, a2n Addr2Name) (links []link.Link, ignored int) {
	links = make([]link.Link, 0, len(kprobes))

	for _, kp := range kprobes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		addrs := make([]uintptr, 0, len(kp.HookFuncs))
		for _, fn := range kp.HookFuncs {
			if addr, ok := a2n.Name2AddrMap[fn]; ok {
				addrs = append(addrs, addr...)
			} else {
				ignored += 1
				bar.Increment()
				continue
			}
		}

		if len(addrs) == 0 {
			continue
		}

		opts := link.KprobeMultiOptions{Addresses: addrs}
		l, err := link.KprobeMulti(kp.Prog, opts)
		bar.Add(len(kp.HookFuncs))
		if err != nil {
			log.Fatalf("Opening kprobe-multi: %s\n", err)
		}

		links = append(links, l)
	}

	return
}

func NewKprober(ctx context.Context, funcs Funcs, coll *ebpf.Collection, a2n Addr2Name, useKprobeMulti bool, batch uint) *kprober {
	msg := "kprobe"
	if useKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching kprobes (via %s)...\n", msg)

	ignored := 0
	bar := pb.StartNew(len(funcs))

	pwruKprobes := make([]Kprobe, 0, len(funcs))
	funcsByPos := GetFuncsByPos(funcs)
	for pos, fns := range funcsByPos {
		fn, ok := coll.Programs[fmt.Sprintf("kprobe_skb_%d", pos)]
		if ok {
			pwruKprobes = append(pwruKprobes, Kprobe{HookFuncs: fns, Prog: fn})
		} else {
			ignored += len(fns)
			bar.Add(len(fns))
		}
	}

	var k kprober
	k.kprobeMulti = useKprobeMulti
	k.kprobeBatch = batch

	if !useKprobeMulti {
		l, i := AttachKprobes(ctx, bar, pwruKprobes, batch)
		k.links = l
		ignored += i
	} else {
		l, i := AttachKprobeMulti(ctx, bar, pwruKprobes, a2n)
		k.links = l
		ignored += i
	}
	bar.Finish()
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	log.Printf("Attached (ignored %d)\n", ignored)

	return &k
}

func NewNonSkbFuncsKprober(nonSkbFuncs []string, funcs Funcs, coll *ebpf.Collection) *kprober {
	slices.Sort(nonSkbFuncs)
	nonSkbFuncs = slices.Compact(nonSkbFuncs)

	var k kprober
	k.kprobeBatch = uint(len(nonSkbFuncs))

	for _, fn := range nonSkbFuncs {
		if _, ok := funcs[fn]; ok {
			continue
		}

		if strings.HasSuffix(fn, "[bpf]") {
			// Skip bpf progs
			continue
		}

		kp, err := link.Kprobe(fn, coll.Programs["kprobe_skb_by_stackid"], nil)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			log.Printf("Opening non-skb-kprobe %s: %s\n", fn, err)
		} else {
			k.links = append(k.links, kp)
		}
	}

	return &k
}
