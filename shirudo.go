// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package main

import (
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	flag "github.com/spf13/pflag"

	"github.com/cilium/pwru/internal/libpcap"
	"github.com/cilium/pwru/internal/pwru"
	"github.com/cilium/pwru/internal/shirudo"
)

//go:embed bpf/shirudo_pwru.lua
var shirudoDecoder []byte

// The options a shirudo upatch carries out on its target. Every other
// one asks for what runs in pwru, which does not run there.
var shirudoFlags = []string{
	"kernel-btf", "filter-func", "filter-netns", "filter-mark",
	"filter-skb-expr", "debug",
	"shirudo-upatch", "shirudo-keys-dir", "shirudo-name",
	"shirudo-available-funcs",
}

func shirudoRefuseFlags() error {
	var refused []string
	flag.Visit(func(f *flag.Flag) {
		if !slices.Contains(shirudoFlags, f.Name) {
			refused = append(refused, "--"+f.Name)
		}
	})
	if len(refused) > 0 {
		return fmt.Errorf("a shirudo upatch cannot carry %s", strings.Join(refused, ", "))
	}
	return nil
}

// shirudoNetns is the inode of --filter-netns, which only an inode names
// on another host.
func shirudoNetns(netns string) (uint32, error) {
	if netns == "" {
		return 0, nil
	}
	inode, ok := strings.CutPrefix(netns, "inode:")
	if !ok {
		return 0, errors.New("--filter-netns of a shirudo upatch takes inode:<inode> alone")
	}
	n, err := strconv.ParseUint(inode, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("--filter-netns %s: %w", netns, err)
	}
	return uint32(n), nil
}

func shirudoKernel(flags pwru.Flags) (*btf.Spec, map[string]struct{}, error) {
	var (
		kernel    *btf.Spec
		available map[string]struct{}
		err       error
	)
	if flags.KernelBTF != "" {
		kernel, err = btf.LoadSpec(flags.KernelBTF)
	} else {
		kernel, err = btf.LoadKernelSpec()
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load the kernel BTF: %w", err)
	}
	if flags.ShirudoFuncs != "" {
		available, err = pwru.ReadAvailableFilterFunctions(flags.ShirudoFuncs)
		if err != nil {
			return nil, nil, fmt.Errorf("read the available functions: %w", err)
		}
	}
	return kernel, available, nil
}

func shirudoSetFilters(spec *ebpf.CollectionSpec, flags pwru.Flags) error {
	netns, err := shirudoNetns(flags.FilterNetns)
	if err != nil {
		return err
	}
	for name, value := range map[string]uint32{
		"pwru_netns":     netns,
		"pwru_mark":      flags.FilterMark & flags.FilterMarkMask,
		"pwru_mark_mask": flags.FilterMarkMask,
	} {
		if err := spec.Variables[name].Set(value); err != nil {
			return fmt.Errorf("set %s: %w", name, err)
		}
	}
	return nil
}

// shirudoPrograms injects the filters into the probe of each position of
// the sk_buff among the arguments, and returns the attach metadata of
// those some function takes it at, deleting the others.
func shirudoPrograms(spec *ebpf.CollectionSpec, kernel *btf.Spec, funcs pwru.Funcs, flags pwru.Flags) (map[string]shirudo.Program, error) {
	progs := map[string]shirudo.Program{
		"shirudo_serialize__events": {Role: shirudo.RoleSerializer, Map: "events"},
		"shirudo_test__pwru":        {Role: shirudo.RoleTestRun},
	}
	byPos := pwru.GetFuncsByPos(funcs)
	for pos := 1; pos <= 5; pos++ {
		name := fmt.Sprintf("pwru_skb_%d", pos)
		prog := spec.Programs[name]
		if prog == nil {
			return nil, fmt.Errorf("the upatch object has no program %s", name)
		}
		if len(byPos[pos]) == 0 {
			delete(spec.Programs, name)
			continue
		}
		if err := libpcap.InjectFilters(prog, flags.FilterPcap, "", ""); err != nil {
			return nil, fmt.Errorf("inject the pcap filter into %s: %w", name, err)
		}
		if err := pwru.InjectFilterSkbExpr(prog, kernel, flags.FilterSkbExpr); err != nil {
			return nil, fmt.Errorf("inject the skb filter into %s: %w", name, err)
		}
		progs[name] = shirudo.Program{
			Role:    shirudo.RoleAttach,
			Kind:    shirudo.KindKprobeMulti,
			Symbols: byPos[pos],
		}
	}
	return progs, nil
}

// exportShirudo writes a shirudo upatch that records on its target the
// packets the filters match at the functions that take an sk_buff, as
// pwru would print them. --kernel-btf and --shirudo-available-funcs
// describe the target's kernel when it is not this host's.
func exportShirudo(flags pwru.Flags) error {
	if err := shirudoRefuseFlags(); err != nil {
		return err
	}
	if flags.ShirudoKeysDir == "" {
		return errors.New("--shirudo-upatch needs --shirudo-keys-dir")
	}
	signer, err := shirudo.LoadSignerDir(flags.ShirudoKeysDir)
	if err != nil {
		return fmt.Errorf("load the signing key: %w", err)
	}
	kernel, available, err := shirudoKernel(flags)
	if err != nil {
		return err
	}

	var funcs pwru.Funcs
	if available != nil {
		funcs, _, err = pwru.GetFuncsFrom(flags.FilterFunc, kernel, nil, true, false, available)
	} else {
		funcs, _, err = pwru.GetFuncs(flags.FilterFunc, kernel, nil, true, false)
	}
	if err != nil {
		return fmt.Errorf("find the functions that take an sk_buff: %w", err)
	}
	if len(funcs) == 0 {
		return errors.New("no matching kernel function takes an sk_buff")
	}

	spec, err := LoadShirudoPWRU()
	if err != nil {
		return fmt.Errorf("load the upatch object: %w", err)
	}
	if err := shirudoSetFilters(spec, flags); err != nil {
		return err
	}
	progs, err := shirudoPrograms(spec, kernel, funcs, flags)
	if err != nil {
		return err
	}

	upatch, err := shirudo.Build(spec, kernel, shirudo.Upatch{
		Name:     flags.ShirudoName,
		Programs: progs,
		Decoders: []shirudo.Decoder{{
			Map:        "events",
			Source:     "pwru.lua",
			Entrypoint: "decode",
			Code:       shirudoDecoder,
		}},
	}, signer)
	if err != nil {
		return fmt.Errorf("build the upatch: %w", err)
	}
	if err := os.WriteFile(flags.ShirudoUpatch, upatch, 0o644); err != nil {
		return err
	}
	slog.Info("Wrote the shirudo upatch", "file", flags.ShirudoUpatch,
		"name", flags.ShirudoName, "functions", len(funcs))
	return nil
}
