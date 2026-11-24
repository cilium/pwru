// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package shirudo

import (
	"fmt"

	"github.com/cilium/ebpf"
	ebpfsl "github.com/cilium/ebpf-sl"
	"github.com/cilium/ebpf-sl/signable"
	"github.com/cilium/ebpf/btf"
)

// Upatch is what goes into a .upatch besides its programs and maps.
type Upatch struct {
	Name string
	// The attach metadata of every program of the collection, by name.
	Programs map[string]Program
	Decoders []Decoder
}

// Build generates with ebpf-sl the loader of spec for the kernel whose
// BTF is given, signs it with the data it loads and the signed sections,
// and returns the .upatch file.
func Build(spec *ebpf.CollectionSpec, kernel *btf.Spec, u Upatch, signer *Signer) ([]byte, error) {
	if err := ValidName(u.Name); err != nil {
		return nil, err
	}
	lowered, pre, err := lower(spec, kernel)
	if err != nil {
		return nil, err
	}
	sl, err := ebpfsl.NewLoaderFromSpec(lowered)
	if err != nil {
		return nil, fmt.Errorf("generate the loader: %w", err)
	}
	if err := fixAddrSpaceCasts(sl, lowered); err != nil {
		return nil, err
	}

	var (
		mapSlots, progSlots []int
		progs               []Program
	)
	for i, slot := range sl.FDSlots {
		switch {
		case slot.Map != nil:
			mapSlots = append(mapSlots, i)
		case slot.Prog != nil:
			p, ok := u.Programs[*slot.Prog]
			if !ok {
				return nil, fmt.Errorf("program %s has no attach metadata", *slot.Prog)
			}
			p.Name = *slot.Prog
			progs = append(progs, p)
			progSlots = append(progSlots, i)
		}
	}
	if len(progs) != len(u.Programs) {
		return nil, fmt.Errorf("attach metadata for %d programs, the collection has %d", len(u.Programs), len(progs))
	}

	insns, data, err := buildShim(sl, pre, mapSlots, progSlots)
	if err != nil {
		return nil, err
	}
	name, err := cstring(u.Name, nameMax)
	if err != nil {
		return nil, fmt.Errorf("upatch name: %w", err)
	}
	attach, err := marshalAttach(progs, len(mapSlots))
	if err != nil {
		return nil, err
	}
	sections := []section{{tagName, name}, {tagAttach, attach}}
	if len(u.Decoders) > 0 {
		decoders, err := marshalDecoders(u.Name, u.Decoders)
		if err != nil {
			return nil, err
		}
		sections = append(sections, section{tagDecoders, decoders})
	}
	data, err = appendSections(data, sections)
	if err != nil {
		return nil, err
	}

	signed := &signable.Loader{Insns: insns, Metadata: data}
	if err := signer.sign(signed); err != nil {
		return nil, err
	}
	c := container{
		name:      u.Name,
		insns:     insns,
		signature: signed.Signature,
		data:      data,
		nrMaps:    len(mapSlots),
		nrProgs:   len(progSlots),
	}
	return c.marshal()
}
