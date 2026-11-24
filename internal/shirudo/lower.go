// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package shirudo

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/sys"
)

// preload is a global data map with an initial value, which ebpf-sl does
// not fill: the shim creates and fills it, and freezes .rodata, before
// the loader runs, which then finds its descriptor in the map's slot.
type preload struct {
	name   string
	spec   *ebpf.MapSpec
	value  []byte
	freeze bool
}

func isDataSection(name string) bool {
	for _, prefix := range []string{".rodata", ".data", ".bss"} {
		if name == prefix || strings.HasPrefix(name, prefix+".") {
			return true
		}
	}
	return false
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// sectionValue returns the initial value of the data section name: its
// contents with the values of its variables over them. cilium/ebpf keeps
// the two apart until it loads a collection, which the export never
// does, so a VariableSpec.Set reaches only the variable.
func sectionValue(spec *ebpf.CollectionSpec, name string, m *ebpf.MapSpec) ([]byte, error) {
	value, ok := m.Contents[0].Value.([]byte)
	if !ok || len(value) != int(m.ValueSize) {
		return nil, fmt.Errorf("map %s: contents are not one value of %d bytes", name, m.ValueSize)
	}
	value = slices.Clone(value)

	var vars []*ebpf.VariableSpec
	for _, v := range spec.Variables {
		if v.SectionName == name {
			vars = append(vars, v)
		}
	}
	slices.SortFunc(vars, func(a, b *ebpf.VariableSpec) int {
		return cmp.Compare(a.Offset, b.Offset)
	})
	var end uint64
	for _, v := range vars {
		if uint64(v.Offset) < end {
			return nil, fmt.Errorf("map %s: variable %s overlaps the one before it", name, v.Name)
		}
		end = uint64(v.Offset) + uint64(v.Size())
		if end > uint64(len(value)) {
			return nil, fmt.Errorf("map %s: variable %s ends past the section", name, v.Name)
		}
		copy(value[v.Offset:end], v.Value)
	}
	return value, nil
}

// lowerMaps strips the contents of the global data maps, which ebpf-sl
// refuses, and returns those the shim must fill. Their BTF goes too: the
// verifier needs none for plain loads and stores, and a .bss of arena
// pointers only adds type tags the target would have to load.
func lowerMaps(spec *ebpf.CollectionSpec) ([]preload, error) {
	var pre []preload

	for _, name := range slices.Sorted(maps.Keys(spec.Maps)) {
		m := spec.Maps[name]
		if m.Contents == nil {
			continue
		}
		if !isDataSection(name) || len(m.Contents) != 1 {
			return nil, fmt.Errorf("map %s has contents, which only a global data section may have", name)
		}
		value, err := sectionValue(spec, name, m)
		if err != nil {
			return nil, err
		}
		m.Contents = nil
		m.Key, m.Value = nil, nil

		freeze := m.Flags&sys.BPF_F_RDONLY_PROG != 0
		if !freeze && allZero(value) {
			continue
		}
		pre = append(pre, preload{name: name, spec: m, value: value, freeze: freeze})
	}
	return pre, nil
}

// relocateCORE applies the CO-RE relocations of insns for kernel, which
// libbpf's loader would apply on the target, and ebpf-sl does not.
func relocateCORE(insns asm.Instructions, kernel *btf.Spec) error {
	var (
		relos     []*btf.CORERelocation
		reloInsns []*asm.Instruction
	)

	iter := insns.Iterate()
	for iter.Next() {
		if relo := btf.CORERelocationMetadata(iter.Ins); relo != nil {
			relos = append(relos, relo)
			reloInsns = append(reloInsns, iter.Ins)
		}
	}
	if len(relos) == 0 {
		return nil
	}

	noLocalIDs := func(btf.Type) (btf.TypeID, error) {
		return 0, errors.New("local type IDs are not supported")
	}
	fixups, err := btf.CORERelocate(relos, []*btf.Spec{kernel}, le, noLocalIDs)
	if err != nil {
		return err
	}
	for i, fixup := range fixups {
		if err := fixup.Apply(reloInsns[i]); err != nil {
			return fmt.Errorf("fixup for %s: %w", relos[i], err)
		}
		*reloInsns[i] = btf.WithCORERelocationMetadata(*reloInsns[i], nil)
	}
	return nil
}

// resolveKfuncs points each kfunc call at the function's type in kernel,
// the vmlinux BTF, as libbpf's loader would on the target.
func resolveKfuncs(insns asm.Instructions, kernel *btf.Spec) error {
	iter := insns.Iterate()
	for iter.Next() {
		fn, _, ok := ebpf.GetKfuncMeta(iter.Ins)
		if !ok {
			continue
		}
		if !iter.Ins.IsKfuncCall() {
			return fmt.Errorf("kfunc %s: only calls are supported", fn.Name)
		}

		var target *btf.Func
		if err := kernel.TypeByName(fn.Name, &target); err != nil {
			return fmt.Errorf("kfunc %s: %w", fn.Name, err)
		}
		if err := btf.CheckTypeCompatibility(fn.Type, target.Type); err != nil {
			return fmt.Errorf("kfunc %s: %w", fn.Name, err)
		}
		id, err := kernel.TypeID(target)
		if err != nil {
			return fmt.Errorf("kfunc %s: %w", fn.Name, err)
		}
		iter.Ins.Constant = int64(id)
		iter.Ins.Offset = 0
	}
	return nil
}

// lower turns spec into one ebpf-sl can generate a loader for. ebpf-sl
// loads instructions as they are, so what libbpf's loader resolves on the
// target is resolved here, for the kernel whose BTF is given: CO-RE
// relocations and kfunc calls. The upatch then loads on that kernel
// build alone, as the functions it attaches to already tie it to one.
// The target attaches the programs from the signed attach metadata, so
// their section's attach point goes.
func lower(spec *ebpf.CollectionSpec, kernel *btf.Spec) (*ebpf.CollectionSpec, []preload, error) {
	out := spec.Copy()

	pre, err := lowerMaps(out)
	if err != nil {
		return nil, nil, err
	}
	for name, p := range out.Programs {
		if p.AttachTarget != nil {
			return nil, nil, fmt.Errorf("program %s: an attach target program is not supported", name)
		}
		p.AttachTo = ""
		if err := relocateCORE(p.Instructions, kernel); err != nil {
			return nil, nil, fmt.Errorf("program %s: %w", name, err)
		}
		if err := resolveKfuncs(p.Instructions, kernel); err != nil {
			return nil, nil, fmt.Errorf("program %s: %w", name, err)
		}
	}
	return out, pre, nil
}
