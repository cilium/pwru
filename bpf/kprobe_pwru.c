// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

#define CFG_FILTER_KEY_DEFAULT    0
#define CFG_MAX            1

#define PRINT_SKB_STR_SIZE    2048

struct skb_meta {
	u32 mark;
	u32 ifindex;
	u32 len;
	u32 mtu;
	u16 protocol;
	u16 pad;
} __attribute__((packed));;

struct tuple {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8 proto;
	u8 pad[7];
} __attribute__((packed));;

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
	u16 pad;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

union v6addr {
	struct {
		u32 p1;
		u32 p2;
		u32 p3;
		u32 p4;
	};
	struct {
		u64 d1;
		u64 d2;
	};
	__u8 addr[16];
} __attribute__((packed));

struct filter_cfg {
	u32 mark;
	u8 ipv6;
	union v6addr saddr;
	union v6addr daddr;
	u8 l4_proto;
	u16 sport;
	u16 dport;
	u8 output_timestamp;
	u8 output_meta;
	u8 output_tuple;
	u8 output_skb;
	u8 pad[2];

} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CFG_MAX);
	__type(key, u32);
	__type(value, struct filter_cfg);
} cfg_map SEC(".maps");

#ifdef OUTPUT_SKB
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, char[PRINT_SKB_STR_SIZE]);
} print_skb_map SEC(".maps");
#endif

static __always_inline bool
filter_mark(struct sk_buff *skb, struct filter_cfg *cfg) {
	u32 mark;

	if (cfg->mark) {
		mark = BPF_CORE_READ(skb, mark);
		return mark == cfg->mark;
	}

	return true;
}

/*
 * Filter by packet tuple, return true when the tuple is empty, return false
 * if one of the other fields does not match.
 */
static __always_inline bool
filter_l3_and_l4(struct sk_buff *skb, struct filter_cfg *cfg) {
	unsigned char *skb_head = 0;
	u16 l3_off, l4_off;
	u16 dport;
	u16 sport;
	u8 iphdr_first_byte;
	u8 ip_vsn;

	if (!cfg->l4_proto && \
        cfg->saddr.d1 == 0 && cfg->saddr.d2 == 0 && \
        cfg->daddr.d1 == 0 && cfg->daddr.d2 == 0 && \
        !cfg->sport && !cfg->dport)
		return true;

	skb_head = BPF_CORE_READ(skb, head);
	l3_off = BPF_CORE_READ(skb, network_header);
	l4_off = BPF_CORE_READ(skb, transport_header);

	struct iphdr *tmp = (struct iphdr *) (skb_head + l3_off);
	bpf_probe_read(&iphdr_first_byte, 1, tmp);
	ip_vsn = iphdr_first_byte >> 4;

	//TODO: support ipv6
	if (ip_vsn != 4) {
		return false;
	}

	struct iphdr ip4;
	bpf_probe_read(&ip4, sizeof(ip4), tmp);

	if (cfg->saddr.p1 != 0 && ip4.saddr != cfg->saddr.p1)
		return false;

	if (cfg->daddr.p1 != 0 && ip4.daddr != cfg->daddr.p1)
		return false;

	if (cfg->l4_proto && ip4.protocol != cfg->l4_proto)
		return false;

	if (cfg->dport || cfg->sport) {
		if (ip4.protocol == IPPROTO_TCP) {
			struct tcphdr *tmp = (struct tcphdr *) (skb_head + l4_off);
			struct tcphdr tcp;

			bpf_probe_read(&tcp, sizeof(tcp), tmp);
			sport = tcp.source;
			dport = tcp.dest;
		} else if (ip4.protocol == IPPROTO_UDP) {
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
filter(struct sk_buff *skb, struct filter_cfg *cfg) {
	return filter_mark(skb, cfg) && filter_l3_and_l4(skb, cfg);
}

static __always_inline void
set_meta(struct sk_buff *skb, struct skb_meta *meta) {
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
	bpf_probe_read(&tpl->proto, 1, &ip->protocol);

	bpf_probe_read(&iphdr_first_byte, 1, ip);
	ip_vsn = iphdr_first_byte >> 4;
	if (ip_vsn == 4) {
		bpf_probe_read(&tpl->saddr, sizeof(tpl->saddr), &ip->saddr);
		bpf_probe_read(&tpl->daddr, sizeof(tpl->daddr), &ip->daddr);
		bpf_probe_read(tpl->pad, sizeof(u32), &ip->daddr);
	}

	if (tpl->proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
		bpf_probe_read(&tpl->sport, sizeof(tpl->sport), &tcp->source);
		bpf_probe_read(&tpl->dport, sizeof(tpl->dport), &tcp->dest);
	} else if (tpl->proto == IPPROTO_UDP) {
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

	str = bpf_map_lookup_elem(&print_skb_map, (u32 *)&id);
	if (!str)
		return;

	if (bpf_snprintf_btf(str, PRINT_SKB_STR_SIZE, &p, sizeof(p), 0) < 0)
		return;

	*event_id = id;
#endif
}

static __always_inline void
set_output(struct sk_buff *skb, struct event_t *event, struct filter_cfg *cfg) {
	if (cfg->output_meta)
		set_meta(skb, &event->meta);

	if (cfg->output_tuple)
		set_tuple(skb, &event->tuple);

	if (cfg->output_skb)
		set_skb_btf(skb, &event->print_skb_id);
}

static __always_inline int
handle_everything(struct sk_buff *skb, struct pt_regs *ctx) {
	struct event_t event = {};

	u32 index = CFG_FILTER_KEY_DEFAULT;
	struct filter_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &index);

	if (cfg) {
		if (!filter(skb, cfg))
			return 0;

		set_output(skb, &event, cfg);
	}

	event.pid = bpf_get_current_pid_tgid();
	event.addr = PT_REGS_IP(ctx);
	event.skb_addr = (u64) skb;
	event.ts = bpf_ktime_get_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

SEC("kprobe/skb-1")
int kprobe_skb_1(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM1(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-2")
int kprobe_skb_2(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM2(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-3")
int kprobe_skb_3(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM3(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-4")
int kprobe_skb_4(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM4(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-5")
int kprobe_skb_5(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM5(ctx);

	return handle_everything(skb, ctx);
}

char __license[] SEC("license") = "GPL";
