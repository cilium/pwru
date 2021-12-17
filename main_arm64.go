// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2021 Authors of Cilium */

//go:generate sh -c "echo Generating for $(go env GOARCH)"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang KProbePWRU ./bpf/kprobe_pwru.c -- -DOUTPUT_SKB -D__TARGET_ARCH_arm64 -I./bpf/headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang KProbePWRUWithoutOutputSKB ./bpf/kprobe_pwru.c -- -D__TARGET_ARCH_arm64 -I./bpf/headers

package main
