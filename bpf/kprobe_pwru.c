// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#define PRINT_SKB_STR_SIZE    2048

#define ETH_P_IP              0x800
#define ETH_P_IPV6            0x86dd

union addr {
	u32 v4addr;
	struct {
		u64 d1;
		u64 d2;
	} v6addr;
	u64 pad[2];
} __attribute__((packed));

struct skb_meta {
	u32 netns;
	u32 mark;
	u32 ifindex;
	u32 len;
	u32 mtu;
	u16 protocol;
	u16 pad;
} __attribute__((packed));

struct tuple {
	union addr saddr;
	union addr daddr;
	u16 sport;
	u16 dport;
	u16 l3_proto;
	u8 l4_proto;
	u8 pad;
} __attribute__((packed));

u64 print_skb_id = 0;

struct event_t {
	u32 pid;
	u32 type;
	u64 addr;
	u64 skb_addr;
	u64 ts;
	typeof(print_skb_id) print_skb_id;
	struct skb_meta meta;
	struct tuple tuple;
	s64 print_stack_id;
	u32 cpu_id;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct config {
	u32 netns;
	u32 mark;
	u8 ipv6;
	union addr saddr;
	union addr daddr;
	u8 l4_proto;
	u16 sport;
	u16 dport;
	u8 output_timestamp;
	u8 output_meta;
	u8 output_tuple;
	u8 output_skb;
	u8 output_stack;
	u8 pad;
} __attribute__((packed));

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} print_stack_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct config);
} cfg_map SEC(".maps");

#ifdef OUTPUT_SKB
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, char[PRINT_SKB_STR_SIZE]);
} print_skb_map SEC(".maps");
#endif


static __always_inline u32
get_netns(struct sk_buff *skb) {
	u32 netns;

	struct net_device *dev = BPF_CORE_READ(skb, dev);
	// Get netns id. The code below is equivalent to: netns = dev->nd_net.net->ns.inum
	netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);

	// maybe the skb->dev is not init, for this situation, we can get ns by sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0)
	{
		struct sock *sk;
		sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)
		{
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		}
	}

	return netns;
}

static __always_inline bool
filter_meta(struct sk_buff *skb, struct config *cfg) {
	u32 netns, mark;

	if (cfg->netns) {
		netns = get_netns(skb);
		if (netns != cfg->netns)
			return false;
	}

	if (cfg->mark) {
		mark = BPF_CORE_READ(skb, mark);
		return mark == cfg->mark;
	}

	return true;
}

static __always_inline bool
addr_is_zero(union addr a) {
	return a.pad[0] == 0 && a.pad[1] == 0;
}

static __always_inline bool
addr_equal(union addr a, u8 b[16]) {
	u64 *d1 = (u64 *)b;
	if (a.pad[0] != *d1) {
		return false;
	}
	if (a.pad[1] != *(d1 + 1)) {
		return false;
	}
	return true;
}

static __always_inline bool
config_tuple_empty(struct config *cfg) {
	if (!cfg->l4_proto && \
        addr_is_zero(cfg->saddr) && \
        addr_is_zero(cfg->daddr) && \
        !cfg->sport && !cfg->dport)
		return true;

	return false;
}

/*
 * Filter by packet tuple, return true when the tuple is empty, return false
 * if one of the other fields does not match.
 */
static __always_inline bool
filter_l3_and_l4(struct sk_buff *skb, struct config *cfg) {
	unsigned char *skb_head = 0;
	u16 l3_off, l4_off;
	u16 sport, dport, l4_proto;
	u8 iphdr_first_byte, ip_vsn;

	if (config_tuple_empty(cfg)) {
		return true;
	}

	skb_head = BPF_CORE_READ(skb, head);
	l3_off = BPF_CORE_READ(skb, network_header);
	l4_off = BPF_CORE_READ(skb, transport_header);

	struct iphdr *tmp = (struct iphdr *) (skb_head + l3_off);
	bpf_probe_read(&iphdr_first_byte, 1, tmp);
	ip_vsn = iphdr_first_byte >> 4;

	if (ip_vsn == 4) {
		struct iphdr ip4;
		bpf_probe_read(&ip4, sizeof(ip4), tmp);

		if (!addr_is_zero(cfg->saddr) && ip4.saddr != cfg->saddr.v4addr)
			return false;

		if (!addr_is_zero(cfg->daddr) && ip4.daddr != cfg->daddr.v4addr)
			return false;

		l4_proto = ip4.protocol;
	} else if (ip_vsn == 6) {
		struct ipv6hdr ip6;
		bpf_probe_read(&ip6, sizeof(ip6), tmp);

		if (!addr_is_zero(cfg->saddr) && !addr_equal(cfg->saddr, ip6.saddr.in6_u.u6_addr8)) {
			return false;
		}

		if (!addr_is_zero(cfg->daddr) && !addr_equal(cfg->daddr, ip6.daddr.in6_u.u6_addr8)) {
			return false;
		}

		/*
		 * The transport layer protocol is represented in ipv6 by the next header type, but there are other
		 * ipv6 extension headers in the next header, so if we want to parse out the transport layer
		 * protocol, we have to identify all the extension headers, which is a bit troublesome, so let's just
		 * assume that there are no other ipv6 extension headers and the default is to handle layer 4 protocols
		 * directly.
		 */
		l4_proto = ip6.nexthdr;
	} else {
		// Network layer protocols other than ipv4,ipv6, ignore for now
		return false;
	}

	if (cfg->l4_proto && l4_proto != cfg->l4_proto)
		return false;

	if (cfg->dport || cfg->sport) {
		if (l4_proto == IPPROTO_TCP) {
			struct tcphdr *tmp = (struct tcphdr *) (skb_head + l4_off);
			struct tcphdr tcp;

			bpf_probe_read(&tcp, sizeof(tcp), tmp);
			sport = tcp.source;
			dport = tcp.dest;
		} else if (l4_proto == IPPROTO_UDP) {
			struct udphdr *tmp = (struct udphdr *) (skb_head + l4_off);
			struct udphdr udp;

			bpf_probe_read(&udp, sizeof(udp), tmp);
			sport = udp.source;
			dport = udp.dest;
		} else {
			return false;
		}

		if (cfg->sport && sport != cfg->sport)
			return false;

		if (cfg->dport && dport != cfg->dport)
			return false;
	}


	return true;
}

static __always_inline bool
filter(struct sk_buff *skb, struct config *cfg) {
	return filter_meta(skb, cfg) && filter_l3_and_l4(skb, cfg);
}

static __always_inline void
set_meta(struct sk_buff *skb, struct skb_meta *meta) {
	meta->netns = get_netns(skb);
	meta->mark = BPF_CORE_READ(skb, mark);
	meta->len = BPF_CORE_READ(skb, len);
	meta->protocol = BPF_CORE_READ(skb, protocol);
	meta->ifindex = BPF_CORE_READ(skb, dev, ifindex);
	meta->mtu = BPF_CORE_READ(skb, dev, mtu);
}

static __always_inline void
set_tuple(struct sk_buff *skb, struct tuple *tpl) {
	unsigned char *skb_head = 0;
	u16 l3_off;
	u16 l4_off;
	struct iphdr *ip;
	u8 iphdr_first_byte;
	u8 ip_vsn;

	skb_head = BPF_CORE_READ(skb, head);
	l3_off = BPF_CORE_READ(skb, network_header);
	l4_off = BPF_CORE_READ(skb, transport_header);

	ip = (struct iphdr *) (skb_head + l3_off);
	bpf_probe_read(&iphdr_first_byte, 1, ip);
	ip_vsn = iphdr_first_byte >> 4;

	if (ip_vsn == 4) {
		bpf_probe_read(&tpl->saddr, sizeof(tpl->saddr.v4addr), &ip->saddr);
		bpf_probe_read(&tpl->daddr, sizeof(tpl->daddr.v4addr), &ip->daddr);
		bpf_probe_read(&tpl->l4_proto, 1, &ip->protocol);
		tpl->l3_proto = ETH_P_IP;
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) ip;
		bpf_probe_read(&tpl->saddr, sizeof(tpl->saddr), &ip6->saddr);
		bpf_probe_read(&tpl->daddr, sizeof(tpl->daddr), &ip6->daddr);
		bpf_probe_read(&tpl->l4_proto, 1, &ip6->nexthdr);
		tpl->l3_proto = ETH_P_IPV6;
	}

	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
		bpf_probe_read(&tpl->sport, sizeof(tpl->sport), &tcp->source);
		bpf_probe_read(&tpl->dport, sizeof(tpl->dport), &tcp->dest);
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
		bpf_probe_read(&tpl->sport, sizeof(tpl->sport), &udp->source);
		bpf_probe_read(&tpl->dport, sizeof(tpl->dport), &udp->dest);
	}
}

static __always_inline void
set_skb_btf(struct sk_buff *skb, typeof(print_skb_id) *event_id) {
#ifdef OUTPUT_SKB
	static struct btf_ptr p = {};
	typeof(print_skb_id) id;
	char *str;

	p.type_id = bpf_core_type_id_kernel(struct sk_buff);
	p.ptr = skb;
	id = __sync_fetch_and_add(&print_skb_id, 1) % 256;

	str = bpf_map_lookup_elem(&print_skb_map, (u32 *) &id);
	if (!str)
		return;

	if (bpf_snprintf_btf(str, PRINT_SKB_STR_SIZE, &p, sizeof(p), 0) < 0)
		return;

	*event_id = id;
#endif
}

static __always_inline void
set_output(struct pt_regs *ctx, struct sk_buff *skb, struct event_t *event, struct config *cfg) {
	if (cfg->output_meta)
		set_meta(skb, &event->meta);

	if (cfg->output_tuple)
		set_tuple(skb, &event->tuple);

	if (cfg->output_skb)
		set_skb_btf(skb, &event->print_skb_id);

	if (cfg->output_stack) {
		event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
	}
}

static __always_inline int
handle_everything(struct sk_buff *skb, struct pt_regs *ctx,
		  bool has_get_func_ip) {
	struct event_t event = {};

	u32 index = 0;
	struct config *cfg = bpf_map_lookup_elem(&cfg_map, &index);

	if (cfg) {
		if (!filter(skb, cfg))
			return 0;

		set_output(ctx, skb, &event, cfg);
	}

	event.pid = bpf_get_current_pid_tgid();
	if (has_get_func_ip)
		event.addr = bpf_get_func_ip(ctx);
	else
		event.addr = PT_REGS_IP(ctx);
	event.skb_addr = (u64) skb;
	event.ts = bpf_ktime_get_ns();
	event.cpu_id = bpf_get_smp_processor_id();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

SEC("kprobe/skb-1")
int kprobe_skb_1(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);

	return handle_everything(skb, ctx, false);
}

SEC("kprobe/skb-2")
int kprobe_skb_2(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM2(ctx);

	return handle_everything(skb, ctx, false);
}

SEC("kprobe/skb-3")
int kprobe_skb_3(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM3(ctx);

	return handle_everything(skb, ctx, false);
}

SEC("kprobe/skb-4")
int kprobe_skb_4(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM4(ctx);

	return handle_everything(skb, ctx, false);
}

SEC("kprobe/skb-5")
int kprobe_skb_5(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM5(ctx);

	return handle_everything(skb, ctx, false);
}

SEC("kprobe.multi/skb-1")
int kprobe_multi_skb_1(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);

	return handle_everything(skb, ctx, true);
}

SEC("kprobe.multi/skb-2")
int kprobe_multi_skb_2(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM2(ctx);

	return handle_everything(skb, ctx, true);
}

SEC("kprobe.multi/skb-3")
int kprobe_multi_skb_3(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM3(ctx);

	return handle_everything(skb, ctx, true);
}

SEC("kprobe.multi/skb-4")
int kprobe_multi_skb_4(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM4(ctx);

	return handle_everything(skb, ctx, true);
}

SEC("kprobe.multi/skb-5")
int kprobe_multi_skb_5(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM5(ctx);

	return handle_everything(skb, ctx, true);
}

char __license[] SEC("license") = "GPL";
