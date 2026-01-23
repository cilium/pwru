// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package pwru

import (
	"os"
	"syscall"
	"testing"
)

func BenchmarkOutputPrint(b *testing.B) {
	devNull, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		b.Fatal(err)
	}
	defer devNull.Close()

	output := &output{
		flags: &Flags{
			OutputTS:       "none",
			OutputMeta:     true,
			OutputTuple:    true,
			OutputCaller:   false,
			OutputStack:    false,
			OutputSkb:      false,
			OutputShinfo:   false,
			OutputTunnel:   false,
			OutputBpfmap:   false,
			OutputTCPFlags: true,
		},
		lastSeenSkb: make(map[uint64]uint64),
		addr2name: Addr2Name{
			Addr2NameMap: map[uint64]*ksym{
				0xffffffff81000000: {addr: 0xffffffff81000000, name: "test_function"},
			},
			Addr2NameSlice: []*ksym{
				{addr: 0xffffffff81000000, name: "test_function"},
			},
		},
		writer: devNull,
		ifaceCache: map[uint64]map[uint32]string{
			4026531840: {1: "lo", 2: "eth0"},
		},
		procCache: map[int]string{
			1234: "test-process:1234",
		},
	}

	event := &Event{
		PID:       1234,
		Type:      eventTypeKprobe,
		Addr:      0xffffffff81000000,
		SkbAddr:   0xffff888012345678,
		Timestamp: 1000000000,
		CPU:       0,
		Meta: Meta{
			Netns:   4026531840,
			Mark:    0x100,
			Ifindex: 2,
			Proto:   0x0800,
			MTU:     1500,
			Len:     64,
		},
		Tuple: Tuple{
			Saddr:   [16]byte{192, 168, 1, 10},
			Daddr:   [16]byte{192, 168, 1, 20},
			Sport:   12345,
			Dport:   80,
			L3Proto: syscall.ETH_P_IP,
			L4Proto: syscall.IPPROTO_TCP,
			TCPFlag: 0x12,
		},
	}

	for b.Loop() {
		output.Print(event)
	}
}
