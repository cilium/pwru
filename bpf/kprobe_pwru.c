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

#define CFG_FILTER_KEY_MARK	0
#define CFG_FILTER_KEY_PROTO	1
#define CFG_FILTER_KEY_SRC_IP	2
#define CFG_FILTER_KEY_DST_IP	3
#define CFG_FILTER_KEY_SRC_PORT	4
#define CFG_FILTER_KEY_DST_PORT	5
#define CFG_OUTPUT_META		6
#define CFG_OUTPUT_TUPLE	7
#define CFG_OUTPUT_SKB		8
#define CFG_MAX			9

#define PRINT_SKB_STR_SIZE	2048

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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CFG_MAX);
	__type(key, u32);
	__type(value, u32);
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
filter_mark(struct sk_buff *skb) {
	u32 mark;
	u32 key_mark = CFG_FILTER_KEY_MARK;
	u32 *val_mark = bpf_map_lookup_elem(&cfg_map, &key_mark);

	if (val_mark) {
		mark = BPF_CORE_READ(skb, mark);
		return mark == *val_mark;
	}

	return true;
}

static __always_inline bool
filter_l3_and_l4(struct sk_buff *skb) {
	unsigned char *skb_head = 0;
	u16 l3_off, l4_off;
	u16 dport;
	u16 sport;
	u8 iphdr_first_byte;
	u8 ip_vsn;

	u32 key_proto = CFG_FILTER_KEY_PROTO;
	u32 *val_proto = bpf_map_lookup_elem(&cfg_map, &key_proto);

	u32 key_src_ip = CFG_FILTER_KEY_SRC_IP;
	u32 *val_src_ip = bpf_map_lookup_elem(&cfg_map, &key_src_ip);

	u32 key_dst_ip = CFG_FILTER_KEY_DST_IP;
	u32 *val_dst_ip = bpf_map_lookup_elem(&cfg_map, &key_dst_ip);

	u32 key_src_port = CFG_FILTER_KEY_SRC_PORT;
	u32 *val_src_port = bpf_map_lookup_elem(&cfg_map, &key_src_port);

	u32 key_dst_port = CFG_FILTER_KEY_DST_PORT;
	u32 *val_dst_port = bpf_map_lookup_elem(&cfg_map, &key_dst_port);

	if (!val_proto && !val_src_ip && !val_dst_ip && !val_src_port && !val_dst_port)
		return true;

	skb_head = BPF_CORE_READ(skb, head);
	l3_off = BPF_CORE_READ(skb, network_header);
	l4_off = BPF_CORE_READ(skb, transport_header);

	struct iphdr *tmp = (struct iphdr *)(skb_head + l3_off);
	struct iphdr ip4;
	bpf_probe_read(&ip4, sizeof(ip4), tmp);

	if (val_proto && ip4.protocol != *val_proto)
		return false;

	bpf_probe_read(&iphdr_first_byte, 1, tmp);
	ip_vsn = iphdr_first_byte >> 4;

	volatile bool src_ip_is_set = val_src_ip;
	volatile bool dst_ip_is_set = val_dst_ip;
	if (ip_vsn != 4 && (src_ip_is_set || dst_ip_is_set))
		return false;

	if (val_src_ip && ip4.saddr != *val_src_ip)
		return false;

	if (val_dst_ip && ip4.daddr != *val_dst_ip)
		return false;

	volatile bool src_port_not_set = !val_src_port;
	volatile bool dst_port_not_set = !val_dst_port;
	if (src_port_not_set && dst_port_not_set)
		return true;

	if (ip4.protocol == IPPROTO_TCP) {
		struct tcphdr *tmp = (struct tcphdr *)(skb_head + l4_off);
		struct tcphdr tcp;

		bpf_probe_read(&tcp, sizeof(tcp), tmp);
		sport = tcp.source;
		dport = tcp.dest;
	} else if (ip4.protocol == IPPROTO_UDP) {
		struct udphdr *tmp = (struct udphdr *)(skb_head + l4_off);
		struct udphdr udp;

		bpf_probe_read(&udp, sizeof(udp), tmp);
		sport = udp.source;
		dport = udp.dest;
	} else {
		return false;
	}

	if (val_src_port && sport != *val_src_port)
	    return false;

	if (val_dst_port && dport != *val_dst_port)
	    return false;

	return true;
}

static __always_inline bool
filter(struct sk_buff *skb) {
	return filter_mark(skb) && filter_l3_and_l4(skb);
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

	ip = (struct iphdr *)(skb_head + l3_off);
	bpf_probe_read(&tpl->proto, 1, &ip->protocol);

	bpf_probe_read(&iphdr_first_byte, 1, ip);
	ip_vsn = iphdr_first_byte >> 4;
	if (ip_vsn == 4) {
		bpf_probe_read(&tpl->saddr, sizeof(tpl->saddr), &ip->saddr);
		bpf_probe_read(&tpl->daddr, sizeof(tpl->daddr), &ip->daddr);
	}

	if (tpl->proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *)(skb_head + l4_off);
		bpf_probe_read(&tpl->sport, sizeof(tpl->sport), &tcp->source);
		bpf_probe_read(&tpl->dport, sizeof(tpl->dport), &tcp->dest);
	} else if (tpl->proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *)(skb_head + l4_off);
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
set_output(struct sk_buff *skb, struct event_t *event) {
	u32 key;

	key = CFG_OUTPUT_META;
	if (bpf_map_lookup_elem(&cfg_map, &key))
		set_meta(skb, &event->meta);

	key = CFG_OUTPUT_TUPLE;
	if (bpf_map_lookup_elem(&cfg_map, &key))
		set_tuple(skb, &event->tuple);

	key = CFG_OUTPUT_SKB;
	if (bpf_map_lookup_elem(&cfg_map, &key))
		set_skb_btf(skb, &event->print_skb_id);
}

static __always_inline int
handle_everything(struct sk_buff *skb, struct pt_regs *ctx)
{
	struct event_t event = {};

	if (!filter(skb))
		return 0;

	set_output(skb, &event);

	event.pid = bpf_get_current_pid_tgid();
	event.addr = PT_REGS_IP(ctx);
	event.skb_addr = (u64)skb;
	event.ts = bpf_ktime_get_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

SEC("kprobe/skb-1")
int kprobe_skb_1(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-2")
int kprobe_skb_2(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-3")
int kprobe_skb_3(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM3(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-4")
int kprobe_skb_4(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM4(ctx);

	return handle_everything(skb, ctx);
}

SEC("kprobe/skb-5")
int kprobe_skb_5(struct pt_regs *ctx) {
	struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM5(ctx);

	return handle_everything(skb, ctx);
}

char __license[] SEC("license") = "GPL";
