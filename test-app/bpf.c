// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

//go:build ignore
 

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("xdp")
int xdp_dummy_prog(struct xdp_md *ctx) {
  return XDP_PASS;
}

SEC("tc/ingress")
int tc_dummy_prog(struct sk_buff *skb) {
  return 0;
}
