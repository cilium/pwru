// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf/btf"

	"github.com/cilium/pwru/internal/pwru"
	"github.com/cilium/pwru/internal/shirudo"
)

// testKeysDir writes a key and certificate as shirudo genkey does.
func testKeysDir(t *testing.T) string {
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
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, shirudo.KeyFile),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, shirudo.CertFile), cert, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The upatch object lowers for this host's kernel with the filters in.
func TestShirudoBuild(t *testing.T) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Skipf("no kernel BTF: %v", err)
	}
	signer, err := shirudo.LoadSignerDir(testKeysDir(t))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := LoadShirudoPWRU()
	if err != nil {
		t.Fatal(err)
	}
	flags := pwru.Flags{
		FilterPcap:     "udp and host 127.0.0.2 and port 4242",
		FilterNetns:    "inode:4026531840",
		FilterMark:     0x1100,
		FilterMarkMask: 0xf00,
		FilterSkbExpr:  "skb->len > 10",
	}
	if err := shirudoSetFilters(spec, flags); err != nil {
		t.Fatal(err)
	}
	funcs := pwru.Funcs{"ip_rcv_core": 1, "__dev_queue_xmit": 1, "sk_skb_reason_drop": 2}
	progs, err := shirudoPrograms(spec, kernel, funcs, flags)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pwru_skb_3", "pwru_skb_4", "pwru_skb_5"} {
		if _, ok := spec.Programs[name]; ok {
			t.Errorf("%s probes no function, but is kept", name)
		}
	}
	if len(progs["pwru_skb_1"].Symbols) != 2 || len(progs["pwru_skb_2"].Symbols) != 1 {
		t.Errorf("attach metadata %+v", progs)
	}

	upatch, err := shirudo.Build(spec, kernel, shirudo.Upatch{
		Name:     "pwru",
		Programs: progs,
		Decoders: []shirudo.Decoder{{Map: "events", Source: "pwru.lua", Entrypoint: "decode", Code: shirudoDecoder}},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}

	// The shim fills .rodata from the upatch's data: the mark is matched
	// under its mask, as pwru does.
	rodata := bytes.Clone(spec.Maps[".rodata"].Contents[0].Value.([]byte))
	for name, value := range map[string]uint32{
		"pwru_netns": 4026531840, "pwru_mark": 0x100, "pwru_mark_mask": 0xf00,
	} {
		binary.LittleEndian.PutUint32(rodata[spec.Variables[name].Offset:], value)
	}
	if !bytes.Contains(upatch, rodata) {
		t.Errorf("the upatch does not carry the filters' .rodata % x", rodata)
	}
}

func TestShirudoNetns(t *testing.T) {
	for netns, want := range map[string]uint32{"": 0, "inode:4026531840": 4026531840} {
		if got, err := shirudoNetns(netns); err != nil || got != want {
			t.Errorf("shirudoNetns(%q) = %d, %v", netns, got, err)
		}
	}
	for _, netns := range []string{"/proc/1/ns/net", "inode:", "inode:x", "inode:4294967296"} {
		if _, err := shirudoNetns(netns); err == nil {
			t.Errorf("shirudoNetns(%q) accepted", netns)
		}
	}
}
