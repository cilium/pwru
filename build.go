// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2021 Authors of Cilium */

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip KProbePWRU ./bpf/kprobe_pwru.c -- -DOUTPUT_SKB -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip KProbeMultiPWRU ./bpf/kprobe_pwru.c -- -DOUTPUT_SKB -DHAS_KPROBE_MULTI -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip KProbePWRUWithoutOutputSKB ./bpf/kprobe_pwru.c -- -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip KProbeMultiPWRUWithoutOutputSKB ./bpf/kprobe_pwru.c -- -D HAS_KPROBE_MULTI -I./bpf/headers -Wno-address-of-packed-member

package main
