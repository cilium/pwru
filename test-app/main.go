// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip bpf bpf.c -- -I../bpf/headers
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var (
	ifaceName  = flag.String("iface", "", "iface to attach BPF prog")
	attachType = flag.String("attach-type", "", "attach type ('xdp', 'tc')")
)

func main() {
	flag.Parse()

	if *attachType != "xdp" && *attachType != "tc" {
		log.Fatalf("invalid attach type: %q", *attachType)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("cannot find iface: %q: %s", *ifaceName, err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	var l link.Link

	switch *attachType {
	case "xdp":
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpDummyProg,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("could not attach XDP program: %s", err)
		}
	case "tc":
		l, err = link.AttachTCX(link.TCXOptions{
			Program:   objs.TcDummyProg,
			Attach:    ebpf.AttachTCXIngress,
			Interface: iface.Index,
		})
	}

	if err := l.Pin(fmt.Sprintf("/sys/fs/bpf/test-app-%s", *attachType)); err != nil {
		log.Fatalf("failed to pin: %s", err)
	}
}
