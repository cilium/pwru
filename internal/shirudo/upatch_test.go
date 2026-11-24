// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package shirudo

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	ebpfsl "github.com/cilium/ebpf-sl"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/sys"
)

func testSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "pwru test"},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{key: key, cert: cert}
}

var testRodata = []byte{1, 2, 3, 4, 5, 6, 7, 8}

// r3 = addr_space_cast(r2, 0, 1), as clang emits it for an arena pointer.
var (
	testCast = func() asm.Instruction {
		ins := asm.Mov.Reg(asm.R3, asm.R2)
		ins.Offset, ins.Constant = 1, 1
		return ins
	}()
	testCastBytes = []byte{0xbf, 0x23, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00}
)

// r2 = &.bss + 4, as clang emits it for a global variable, with .bss the
// probe's second map: BPF_PSEUDO_MAP_IDX_VALUE, index 1, offset 4.
var testValueBytes = []byte{
	0x18, 0x62, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
}

func testSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"events": {
				Name: "events", Type: ebpf.Array, KeySize: 4,
				ValueSize: 1, MaxEntries: 1,
			},
			".rodata": {
				Name: ".rodata", Type: ebpf.Array, KeySize: 4,
				ValueSize: uint32(len(testRodata)), MaxEntries: 1,
				Flags:    sys.BPF_F_RDONLY_PROG,
				Contents: []ebpf.MapKV{{Key: uint32(0), Value: slices.Clone(testRodata)}},
			},
			".bss": {
				Name: ".bss", Type: ebpf.Array, KeySize: 4,
				ValueSize: 8, MaxEntries: 1,
				Contents: []ebpf.MapKV{{Key: uint32(0), Value: make([]byte, 8)}},
			},
		},
		Variables: map[string]*ebpf.VariableSpec{
			"filter": {SectionName: ".rodata", Name: "filter", Offset: 4, Value: slices.Clone(testRodata[4:])},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"probe": {
				Name: "probe", Type: ebpf.Kprobe,
				AttachType: ebpf.AttachTraceKprobeMulti, AttachTo: "skb-1",
				License: "Dual BSD/GPL",
				Instructions: asm.Instructions{
					asm.LoadMapValue(asm.R1, 0, 0).WithReference(".rodata"),
					asm.LoadMapValue(asm.R2, 0, 4).WithReference(".bss"),
					testCast,
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
			"serialize": {
				Name: "serialize", Type: ebpf.Syscall,
				Flags: sys.BPF_F_SLEEPABLE, License: "Dual BSD/GPL",
				Instructions: asm.Instructions{
					asm.LoadMapPtr(asm.R1, 0).WithReference("events"),
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
		},
	}
}

var testPrograms = map[string]Program{
	"probe":     {Role: RoleAttach, Kind: KindKprobeMulti, Symbols: []string{"ip_rcv", "dev_queue_xmit", "ip_rcv"}},
	"serialize": {Role: RoleSerializer, Map: "events"},
}

// parsed is a .upatch as a target reads it.
type parsed struct {
	insns, sig, data []byte
	nrMaps, nrProgs  uint32
	sections         map[uint32][]byte
}

func parseUpatch(t *testing.T, b []byte) parsed {
	t.Helper()
	if len(b) < headerSize || le.Uint64(b) != upatchMagic {
		t.Fatal("no upatch header")
	}
	field := func(off int) uint32 { return le.Uint32(b[off:]) }
	slice := func(off, n uint32) []byte {
		if uint64(off)+uint64(n) > uint64(len(b)) {
			t.Fatalf("[%d, +%d) past the end of %d bytes", off, n, len(b))
		}
		return b[off : off+n]
	}
	const fields = 8 + 4 + 4 + nameMax + 32
	p := parsed{
		insns:   slice(field(fields), field(fields+4)),
		sig:     slice(field(fields+8), field(fields+12)),
		data:    slice(field(fields+24), field(fields+28)),
		nrMaps:  field(fields + 36),
		nrProgs: field(fields + 40),
	}
	if name := string(b[16 : 16+nameMax]); !strings.HasPrefix(name, "pwru\x00") {
		t.Errorf("header name %q", name)
	}
	if digest := sha256.Sum256(append(slices.Clone(p.insns), p.data...)); !bytes.Equal(digest[:], b[16+nameMax:16+nameMax+32]) {
		t.Error("payload_sha256 is not SHA-256(insns || data)")
	}

	d := p.data
	trailer := d[len(d)-16:]
	if le.Uint32(trailer) != trailerMagic {
		t.Fatal("no signed trailer")
	}
	dirOff, n := le.Uint32(trailer[8:]), le.Uint32(trailer[12:])
	p.sections = map[uint32][]byte{}
	for i := range n {
		e := d[dirOff+16*i:]
		off, size := le.Uint32(e[8:]), le.Uint32(e[12:])
		if off%8 != 0 {
			t.Errorf("section %x at %d is not 8-byte aligned", le.Uint32(e), off)
		}
		p.sections[le.Uint32(e)] = d[off : off+size]
	}
	return p
}

func TestBuild(t *testing.T) {
	out, err := Build(testSpec(), nil, Upatch{
		Name:     "pwru",
		Programs: testPrograms,
		Decoders: []Decoder{{Map: "events", Source: "pwru.lua", Entrypoint: "decode", Code: []byte("function decode() end")}},
	}, testSigner(t))
	if err != nil {
		t.Fatal(err)
	}
	p := parseUpatch(t, out)

	if p.nrMaps != 3 || p.nrProgs != 2 {
		t.Errorf("%d maps and %d programs, want 3 and 2", p.nrMaps, p.nrProgs)
	}
	if len(p.sig) == 0 {
		t.Error("no signature")
	}
	if name := p.sections[tagName]; len(name) != nameMax || !bytes.HasPrefix(name, []byte("pwru\x00")) {
		t.Errorf("NAME section %q", name)
	}
	if p.sections[tagDecoders] == nil {
		t.Error("no DCDB section")
	}

	attach := p.sections[tagAttach]
	if le.Uint32(attach[8:]) != 2 || le.Uint32(attach[12:]) != 3 {
		t.Fatalf("UPGM counts %d programs and %d maps", le.Uint32(attach[8:]), le.Uint32(attach[12:]))
	}
	const entrySize = 4 + 4 + 8 + progTargetMax + progMapMax
	first, second := attach[16:], attach[16+entrySize:]
	if Role(le.Uint32(first)) != RoleAttach || AttachKind(le.Uint32(first[4:])) != KindKprobeMulti {
		t.Errorf("program 0 is not the kprobe.multi probe")
	}
	if Role(le.Uint32(second)) != RoleSerializer || !bytes.HasPrefix(second[16+progTargetMax:], []byte("events\x00")) {
		t.Errorf("program 1 is not the events serializer")
	}
	upks := attach[16+2*entrySize:]
	if le.Uint32(upks) != kprobeTargetsMagic || le.Uint32(upks[16:]) != 0 || le.Uint32(upks[20:]) != 2 {
		t.Fatalf("UPKS block does not hold program 0's two symbols")
	}
	if syms := string(upks[28 : 28+le.Uint32(upks[24:])]); syms != "dev_queue_xmit\x00ip_rcv\x00" {
		t.Errorf("symbols %q, want sorted and unique", syms)
	}

	if !bytes.Contains(p.data, testRodata) {
		t.Error("the data does not carry .rodata's value")
	}
	if !bytes.Contains(p.data, testCastBytes) {
		t.Error("the probe's addr_space_cast lost its offset")
	}
	if !bytes.Contains(p.data, testValueBytes) {
		t.Error("the probe's load of a .bss variable is not one of its value")
	}
}

// The shim runs first and calls ebpf-sl's loader, which follows it
// unchanged.
func TestShimCallsLoader(t *testing.T) {
	lowered, pre, err := lower(testSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pre) != 1 || pre[0].name != ".rodata" || !pre[0].freeze {
		t.Fatalf("preloads %+v, want .rodata alone, frozen", pre)
	}
	if lowered.Maps[".bss"].Contents != nil || lowered.Programs["probe"].AttachTo != "" {
		t.Fatal("lower left what ebpf-sl refuses")
	}
	sl, err := ebpfsl.NewLoaderFromSpec(lowered)
	if err != nil {
		t.Fatal(err)
	}
	insns, data, err := buildShim(sl, pre, []int{0, 1, 2}, []int{3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(insns, sl.Insns) || !bytes.HasPrefix(data, sl.Metadata) {
		t.Fatal("ebpf-sl's loader or metadata changed")
	}

	decoded, err := asm.AppendInstructions(nil, bytes.NewReader(insns), le, "linux")
	if err != nil {
		t.Fatal(err)
	}
	entry := (len(insns) - len(sl.Insns)) / asm.InstructionSize
	var off, calls int
	var freezes bool
	for _, ins := range decoded {
		if ins.IsFunctionCall() && off < entry {
			calls++
			if target := off + 1 + int(ins.Constant); target != entry {
				t.Errorf("the shim calls %d, ebpf-sl's loader starts at %d", target, entry)
			}
		}
		if off < entry && ins.OpCode == asm.Mov.Op(asm.ImmSource) && ins.Dst == asm.R1 && ins.Constant == int64(sys.BPF_MAP_FREEZE) {
			freezes = true
		}
		off += int(ins.Size()) / asm.InstructionSize
	}
	if calls != 1 {
		t.Errorf("the shim makes %d calls into the loader, want 1", calls)
	}
	if !freezes {
		t.Error("the shim does not freeze .rodata")
	}
}

// .rodata is preloaded with the value set on its variable, which
// cilium/ebpf does not write into the section's contents.
func TestLowerVariables(t *testing.T) {
	spec := testSpec()
	if err := spec.Variables["filter"].Set(uint32(0x09090909)); err != nil {
		t.Fatal(err)
	}
	_, pre, err := lower(spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{1, 2, 3, 4, 9, 9, 9, 9}; len(pre) != 1 || !bytes.Equal(pre[0].value, want) {
		t.Fatalf("preloads %+v, want .rodata of % x", pre, want)
	}
	if !bytes.Equal(spec.Maps[".rodata"].Contents[0].Value.([]byte), testRodata) {
		t.Error("lower changed the spec's .rodata")
	}

	spec.Variables["filter"].Offset = 6
	if _, _, err := lower(spec, nil); err == nil {
		t.Error("a variable past the end of .rodata was accepted")
	}
}

// ebpf-sl loads every program with an fd_array_cnt of the maps it uses:
// probe two, serialize one.
func TestFdArrayCnt(t *testing.T) {
	lowered, _, err := lower(testSpec(), nil)
	if err != nil {
		t.Fatal(err)
	}
	sl, err := ebpfsl.NewLoaderFromSpec(lowered)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := asm.AppendInstructions(nil, bytes.NewReader(sl.Insns), le, "linux")
	if err != nil {
		t.Fatal(err)
	}
	cntOff := int16(unsafe.Offsetof(sys.ProgLoadAttrRaw{}.FdArrayCnt))
	var counts []int64
	for _, ins := range decoded {
		if ins.OpCode.Class() == asm.StClass && ins.Dst == asm.R2 && ins.Offset == cntOff {
			counts = append(counts, ins.Constant)
		}
	}
	if !slices.Equal(counts, []int64{2, 1}) {
		t.Fatalf("fd_array counts %v, want [2 1]", counts)
	}
}

func TestAttachRefuses(t *testing.T) {
	for name, progs := range map[string][]Program{
		"no symbols":      {{Name: "p", Role: RoleAttach, Kind: KindKprobeMulti}},
		"bad symbol":      {{Name: "p", Role: RoleAttach, Kind: KindKprobeMulti, Symbols: []string{"ip_*"}}},
		"other kind":      {{Name: "p", Role: RoleAttach, Kind: 1, Symbols: []string{"f"}}},
		"serializer, map": {{Name: "p", Role: RoleSerializer}},
		"map, no role":    {{Name: "p", Role: RoleTestRun, Map: "m"}},
	} {
		if _, err := marshalAttach(progs, 1); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidName(t *testing.T) {
	for name, ok := range map[string]bool{
		"pwru": true, "pwru-1.2_x": true, "": false, ".pwru": false,
		"pw/ru": false, strings.Repeat("a", 255): true,
		strings.Repeat("a", 256): false, strings.Repeat(".", 128): false,
	} {
		if err := ValidName(name); (err == nil) != ok {
			t.Errorf("ValidName(%q) = %v", name, err)
		}
	}
}

func TestParseKey(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatal(err)
	}
	seedOnly, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	// OpenSSL 3.5 writes the seed together with the expanded key.
	both, err := asn1.Marshal(struct{ Seed, Expanded []byte }{key.Bytes(), make([]byte, 64)})
	if err != nil {
		t.Fatal(err)
	}
	openssl, err := asn1.Marshal(struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidMLDSA87}, both})
	if err != nil {
		t.Fatal(err)
	}

	for name, der := range map[string][]byte{"seed": seedOnly, "seed and expanded key": openssl} {
		got, err := parseKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !got.PublicKey().Equal(key.PublicKey()) {
			t.Errorf("%s: another key", name)
		}
	}
	if _, err := parseKey([]byte("not a key")); err == nil {
		t.Error("accepted no PEM")
	}
}
