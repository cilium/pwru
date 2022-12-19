// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 Authors of Cilium */

//go:generate sh -c "echo Generating for amd64"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang KProbePWRU ./bpf/kprobe_pwru.c -- -DOUTPUT_SKB -D__TARGET_ARCH_x86 -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang KProbeMultiPWRU ./bpf/kprobe_pwru.c -- -DOUTPUT_SKB -DHAS_KPROBE_MULTI -D__TARGET_ARCH_x86 -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang KProbePWRUWithoutOutputSKB ./bpf/kprobe_pwru.c -- -D__TARGET_ARCH_x86 -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang KProbeMultiPWRUWithoutOutputSKB ./bpf/kprobe_pwru.c -- -D HAS_KPROBE_MULTI -D__TARGET_ARCH_x86 -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run ./tools/getgetter.go -struct ^(KProbePWRU|KProbeMultiPWRU|KProbePWRUWithoutOutputSKB|KProbeMultiPWRUWithoutOutputSKB)(Programs|Maps)$

package main
