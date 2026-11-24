// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

// Package shirudo exports pwru as a shirudo upatch: a signed .upatch
// container whose loader cilium/ebpf-sl generates, which a shirudo target
// loads, attaches and reads back without pwru. The layout follows
// shirudo's Documentation/reference/formats/upatch-format.rst.
package shirudo

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

const (
	headerSize    = 360
	upatchMagic   = 0x53485244554e4150 // "PANUDRHS"
	upatchVersion = 1
	typeBPF       = 1
	flagUnload    = 1 << 0
	nameMax       = 256
	fileMax       = 16 << 20
	logBufSize    = 1 << 20

	trailerMagic  = 0x52544753 // "SGTR"
	signedVersion = 1
	sectionsMax   = 8

	tagName     = 0x454d414e // "NAME"
	tagAttach   = 0x4d475055 // "UPGM"
	tagUnload   = 0x444c4e55 // "UNLD"
	tagDecoders = 0x42444344 // "DCDB"

	progMagic     = 0x4d475055 // "UPGM"
	progVersion   = 1
	progTargetMax = 128
	progMapMax    = 16

	kprobeTargetsMagic   = 0x534b5055 // "UPKS"
	kprobeTargetsVersion = 1
	kprobeSymMax         = 512
	kprobeSymsMax        = 1 << 20

	decoderMagic      = 0x42444344 // "DCDB"
	decoderVersion    = 1
	decoderLangLua    = 1
	decoderAPIVersion = 1
	decoderInputMapV1 = 1
	decoderExportLog  = 1
	decoderUpatchMax  = 64
	decoderSourceMax  = 64
	decoderEntryMax   = 32
)

// Role is what the target does with a program the loader created.
type Role uint32

const (
	RoleAttach     Role = 0
	RoleSerializer Role = 1
	RoleTestRun    Role = 2
)

// AttachKind is how the target attaches a program of RoleAttach.
type AttachKind uint32

const (
	KindKprobeMulti AttachKind = 12
)

// Program is the signed attach metadata of one program, in the order of
// the loader's program descriptors.
type Program struct {
	Name    string
	Role    Role
	Kind    AttachKind
	Map     string   // the map a serializer reads
	Symbols []string // the functions a kprobe.multi program attaches to
}

// Decoder is a Lua decoder the target runs on what a map's serializer
// writes.
type Decoder struct {
	Map        string
	Source     string // the name it goes by, a relative path
	Entrypoint string
	Code       []byte
}

// ValidName reports whether name is one a shirudo target accepts for a
// upatch: 1 to 255 characters of [A-Za-z0-9._-], each dot counting as
// two, that do not start with a dot.
func ValidName(name string) error {
	if name == "" || name[0] == '.' {
		return errors.New("upatch name must not be empty or start with '.'")
	}
	n := 0
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '-':
			n++
		case c == '.':
			n += 2
		default:
			return fmt.Errorf("upatch name %q: %q is not one of [A-Za-z0-9._-]", name, c)
		}
	}
	if n >= nameMax {
		return fmt.Errorf("upatch name %q is too long", name)
	}
	return nil
}

func validKprobeSym(sym string) bool {
	if len(sym) == 0 || len(sym) >= kprobeSymMax {
		return false
	}
	for _, c := range []byte(sym) {
		if c <= ' ' || c >= 0x7f || c == ',' || c == '*' || c == '?' || c == '|' {
			return false
		}
	}
	return true
}

// cstring copies s into a NUL-padded field of size n, which must keep a
// NUL.
func cstring(s string, n int) ([]byte, error) {
	if len(s) >= n {
		return nil, fmt.Errorf("%q does not fit %d bytes", s, n-1)
	}
	b := make([]byte, n)
	copy(b, s)
	return b, nil
}

var le = binary.LittleEndian

// marshalAttach lays out the UPGM section: the program entries, then the
// UPKS block of kprobe.multi symbols, each list sorted as strcmp() orders
// it, which the target requires.
func marshalAttach(progs []Program, nrMaps int) ([]byte, error) {
	b := le.AppendUint32(nil, progMagic)
	b = le.AppendUint32(b, progVersion)
	b = le.AppendUint32(b, uint32(len(progs)))
	b = le.AppendUint32(b, uint32(nrMaps))

	nrKprobeMulti := 0
	for _, p := range progs {
		mapField, err := cstring(p.Map, progMapMax)
		if err != nil {
			return nil, fmt.Errorf("program %s: map: %w", p.Name, err)
		}
		switch p.Role {
		case RoleSerializer:
			if p.Map == "" {
				return nil, fmt.Errorf("serializer %s names no map", p.Name)
			}
		case RoleTestRun:
		case RoleAttach:
			if p.Kind != KindKprobeMulti {
				return nil, fmt.Errorf("program %s: attach kind %d is not supported", p.Name, p.Kind)
			}
			nrKprobeMulti++
		default:
			return nil, fmt.Errorf("program %s: unknown role %d", p.Name, p.Role)
		}
		if p.Role != RoleSerializer && p.Map != "" {
			return nil, fmt.Errorf("program %s reads a map but is no serializer", p.Name)
		}
		kind := uint32(0)
		if p.Role == RoleAttach {
			kind = uint32(p.Kind)
		}
		b = le.AppendUint32(b, uint32(p.Role))
		b = le.AppendUint32(b, kind)
		b = le.AppendUint64(b, 0)
		b = append(b, make([]byte, progTargetMax)...)
		b = append(b, mapField...)
	}
	if nrKprobeMulti == 0 {
		return b, nil
	}

	b = le.AppendUint32(b, kprobeTargetsMagic)
	b = le.AppendUint32(b, kprobeTargetsVersion)
	b = le.AppendUint32(b, uint32(nrKprobeMulti))
	b = le.AppendUint32(b, 0)
	for i, p := range progs {
		if p.Role != RoleAttach {
			continue
		}
		syms := slices.Clone(p.Symbols)
		slices.Sort(syms)
		syms = slices.Compact(syms)
		if len(syms) == 0 || len(syms) > kprobeSymsMax {
			return nil, fmt.Errorf("program %s: %d symbols, want 1 to %d", p.Name, len(syms), kprobeSymsMax)
		}
		var names []byte
		for _, s := range syms {
			if !validKprobeSym(s) {
				return nil, fmt.Errorf("program %s: symbol %q cannot be attached to", p.Name, s)
			}
			names = append(names, s...)
			names = append(names, 0)
		}
		b = le.AppendUint32(b, uint32(i))
		b = le.AppendUint32(b, uint32(len(syms)))
		b = le.AppendUint32(b, uint32(len(names)))
		b = append(b, names...)
	}
	return b, nil
}

// marshalDecoders lays out the DCDB section: the entries, then their
// sources behind them.
func marshalDecoders(name string, decoders []Decoder) ([]byte, error) {
	const entrySize = 200

	upatch := name
	if len(upatch) >= decoderUpatchMax {
		upatch = ""
	}
	b := le.AppendUint32(nil, decoderMagic)
	b = le.AppendUint32(b, decoderVersion)
	b = le.AppendUint32(b, uint32(len(decoders)))
	b = le.AppendUint32(b, 0)

	sourceOff := len(b) + entrySize*len(decoders)
	for _, d := range decoders {
		if len(d.Code) == 0 {
			return nil, fmt.Errorf("decoder of map %s is empty", d.Map)
		}
		b = le.AppendUint32(b, decoderLangLua)
		b = le.AppendUint32(b, decoderAPIVersion)
		b = le.AppendUint32(b, decoderInputMapV1)
		b = le.AppendUint32(b, decoderExportLog)
		for _, f := range []struct {
			s string
			n int
		}{{upatch, decoderUpatchMax}, {d.Map, progMapMax}, {d.Source, decoderSourceMax}, {d.Entrypoint, decoderEntryMax}} {
			field, err := cstring(f.s, f.n)
			if err != nil {
				return nil, fmt.Errorf("decoder of map %s: %w", d.Map, err)
			}
			b = append(b, field...)
		}
		b = le.AppendUint32(b, uint32(sourceOff))
		b = le.AppendUint32(b, uint32(len(d.Code)))
		sourceOff += len(d.Code)
	}
	for _, d := range decoders {
		b = append(b, d.Code...)
	}
	return b, nil
}

type section struct {
	tag  uint32
	data []byte
}

func pad8(b []byte) []byte {
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return b
}

// appendSections places the signed sections behind the loader's data,
// each and their directory at an 8-byte boundary, and the trailer that
// locates the directory in the last 16 bytes.
func appendSections(data []byte, sections []section) ([]byte, error) {
	if len(sections) == 0 || len(sections) > sectionsMax {
		return nil, fmt.Errorf("%d signed sections, want 1 to %d", len(sections), sectionsMax)
	}
	type entry struct{ tag, off, len uint32 }
	dir := make([]entry, 0, len(sections))
	for _, s := range sections {
		data = pad8(data)
		dir = append(dir, entry{s.tag, uint32(len(data)), uint32(len(s.data))})
		data = append(data, s.data...)
	}
	data = pad8(data)
	dirOff := len(data)
	for _, e := range dir {
		data = le.AppendUint32(data, e.tag)
		data = le.AppendUint32(data, 0)
		data = le.AppendUint32(data, e.off)
		data = le.AppendUint32(data, e.len)
	}
	data = le.AppendUint32(data, trailerMagic)
	data = le.AppendUint32(data, signedVersion)
	data = le.AppendUint32(data, uint32(dirOff))
	data = le.AppendUint32(data, uint32(len(sections)))
	return data, nil
}

// container is a .upatch file before it is written: the header is not
// signed, the loader instructions and the data, signed sections and
// all, are.
type container struct {
	flags     uint32
	name      string
	insns     []byte
	signature []byte
	data      []byte
	nrMaps    int
	nrProgs   int
}

func payloadSHA256(insns, data []byte) [32]byte {
	h := sha256.New()
	h.Write(insns)
	h.Write(data)
	return [32]byte(h.Sum(nil))
}

func (c *container) marshal() ([]byte, error) {
	if len(c.insns) == 0 || len(c.insns)%8 != 0 {
		return nil, fmt.Errorf("loader of %d bytes is not a whole number of instructions", len(c.insns))
	}
	if len(c.signature) == 0 {
		return nil, errors.New("upatch is not signed")
	}
	size := headerSize + len(c.insns) + len(c.signature) + len(c.data)
	if size > fileMax {
		return nil, fmt.Errorf("upatch of %d bytes exceeds the %d a target reads", size, fileMax)
	}
	name, err := cstring(c.name, nameMax)
	if err != nil {
		return nil, fmt.Errorf("upatch name: %w", err)
	}
	digest := payloadSHA256(c.insns, c.data)
	insnsOff := headerSize
	sigOff := insnsOff + len(c.insns)
	dataOff := sigOff + len(c.signature)

	b := make([]byte, 0, size)
	b = le.AppendUint64(b, upatchMagic)
	b = le.AppendUint32(b, upatchVersion)
	b = le.AppendUint32(b, c.flags)
	b = append(b, name...)
	b = append(b, digest[:]...)
	b = le.AppendUint32(b, uint32(insnsOff))
	b = le.AppendUint32(b, uint32(len(c.insns)))
	b = le.AppendUint32(b, uint32(sigOff))
	b = le.AppendUint32(b, uint32(len(c.signature)))
	b = le.AppendUint32(b, 0) // metadata_off
	b = le.AppendUint32(b, 0) // metadata_len
	b = le.AppendUint32(b, uint32(dataOff))
	b = le.AppendUint32(b, uint32(len(c.data)))
	b = le.AppendUint32(b, logBufSize)
	b = le.AppendUint32(b, uint32(c.nrMaps))
	b = le.AppendUint32(b, uint32(c.nrProgs))
	b = le.AppendUint32(b, 0) // rodata_data_off: no bpm .rodata rewrites
	b = le.AppendUint32(b, typeBPF)
	b = le.AppendUint32(b, 0) // reserved1
	if len(b) != headerSize {
		panic(fmt.Sprintf("upatch header is %d bytes", len(b)))
	}
	b = append(b, c.insns...)
	b = append(b, c.signature...)
	b = append(b, c.data...)
	return b, nil
}
