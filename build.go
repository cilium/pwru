// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 Authors of Cilium */

//go:generate sh -c "echo Generating for $GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -cc clang KProbePWRU ./bpf/kprobe_pwru.c -- -DOUTPUT_SKB -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -cc clang KProbeMultiPWRU ./bpf/kprobe_pwru.c -- -DOUTPUT_SKB -DHAS_KPROBE_MULTI -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -cc clang KProbePWRUWithoutOutputSKB ./bpf/kprobe_pwru.c -- -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -cc clang KProbeMultiPWRUWithoutOutputSKB ./bpf/kprobe_pwru.c -- -D HAS_KPROBE_MULTI -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run ./tools/getgetter.go -struct ^(KProbePWRU|KProbeMultiPWRU|KProbePWRUWithoutOutputSKB|KProbeMultiPWRUWithoutOutputSKB)(Programs|Maps)$

package main
