// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_ipv6.h"

#define PRINT_SKB_STR_SIZE    2048

#define ETH_P_IP              0x800
#define ETH_P_IPV6            0x86dd

const static bool TRUE = true;

union addr {
	u32 v4addr;
	struct {
		u64 d1;
		u64 d2;
	} v6addr;
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
	u64 param_second;
	u32 cpu_id;
} __attribute__((packed));

#define MAX_QUEUE_ENTRIES 10000
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct event_t);
	__uint(max_entries, MAX_QUEUE_ENTRIES);
} events SEC(".maps");

#define MAX_TRACK_SIZE 1024
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, bool);
	__uint(max_entries, MAX_TRACK_SIZE);
} skb_addresses SEC(".maps");

struct config {
	u32 netns;
	u32 mark;
	u32 ifindex;
	u8 output_timestamp;
	u8 output_meta;
	u8 output_tuple;
	u8 output_skb;
	u8 output_stack;
	u8 is_set;
	u8 track_skb;
} __attribute__((packed));

static volatile const struct config CFG;
#define cfg (&CFG)

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} print_stack_map SEC(".maps");

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
	u32 netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

	// if skb->dev is not initialized, try to get ns from sk->__sk_common.skc_net.net->ns.inum
	if (netns == 0)	{
		struct sock *sk = BPF_CORE_READ(skb, sk);
		if (sk != NULL)	{
			netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		}
	}

	return netns;
}

static __always_inline bool
filter_meta(struct sk_buff *skb) {
	if (cfg->netns && get_netns(skb) != cfg->netns) {
			return false;
	}
	if (cfg->mark && BPF_CORE_READ(skb, mark) != cfg->mark) {
		return false;
	}
	if (cfg->ifindex != 0 && BPF_CORE_READ(skb, dev, ifindex) != cfg->ifindex) {
		return false;
	}
	return true;
}

static __noinline bool
filter_pcap_ebpf_l3(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
filter_pcap_l3(struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	void *data = skb_head + BPF_CORE_READ(skb, network_header);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);
	return filter_pcap_ebpf_l3((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __noinline bool
filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data, void* data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __always_inline bool
filter_pcap_l2(struct sk_buff *skb)
{
	void *skb_head = BPF_CORE_READ(skb, head);
	void *data = skb_head + BPF_CORE_READ(skb, mac_header);
	void *data_end = skb_head + BPF_CORE_READ(skb, tail);
	return filter_pcap_ebpf_l2((void *)skb, (void *)skb, (void *)skb, data, data_end);
}

static __always_inline bool
filter_pcap(struct sk_buff *skb) {
	if (BPF_CORE_READ(skb, mac_len) == 0)
		return filter_pcap_l3(skb);
	return filter_pcap_l2(skb);
}

static __always_inline bool
filter(struct sk_buff *skb) {
	return filter_pcap(skb) && filter_meta(skb);
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
	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	u16 l4_off;

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);

	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
		l4_off = l3_off + BPF_CORE_READ_BITFIELD_PROBED(ip4, ihl) * 4;

	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip6, nexthdr); // TODO: ipv6 l4 protocol
		tpl->l3_proto = ETH_P_IPV6;
		l4_off = l3_off + ipv6_hdrlen(ip6);
	}

	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(tcp, source);
		tpl->dport= BPF_CORE_READ(tcp, dest);
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
		tpl->sport= BPF_CORE_READ(udp, source);
		tpl->dport= BPF_CORE_READ(udp, dest);
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
	if (!str) {
		return;
	}

	if (bpf_snprintf_btf(str, PRINT_SKB_STR_SIZE, &p, sizeof(p), 0) < 0) {
		return;
	}

	*event_id = id;
#endif
}

static __always_inline void
set_output(void *ctx, struct sk_buff *skb, struct event_t *event) {
	if (cfg->output_meta) {
		set_meta(skb, &event->meta);
	}

	if (cfg->output_tuple) {
		set_tuple(skb, &event->tuple);
	}

	if (cfg->output_skb) {
		set_skb_btf(skb, &event->print_skb_id);
	}

	if (cfg->output_stack) {
		event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
	}
}

static __noinline bool
handle_everything(struct sk_buff *skb, void *ctx, struct event_t *event) {
	bool tracked = false;
	u64 skb_addr = (u64) skb;

	if (cfg->is_set) {
		if (cfg->track_skb && bpf_map_lookup_elem(&skb_addresses, &skb_addr)) {
			tracked = true;
			goto cont;
		}

		if (!filter(skb)) {
			return false;
		}

cont:
		set_output(ctx, skb, event);
	}

	if (cfg->track_skb && !tracked) {
		bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);
	}

	event->pid = bpf_get_current_pid_tgid();
	event->ts = bpf_ktime_get_ns();
	event->cpu_id = bpf_get_smp_processor_id();

	return true;
}

static __always_inline int
kprobe_skb(struct sk_buff *skb, struct pt_regs *ctx, bool has_get_func_ip) {
	struct event_t event = {};

	if (!handle_everything(skb, ctx, &event))
		return BPF_OK;

	event.skb_addr = (u64) skb;
	event.addr = has_get_func_ip ? bpf_get_func_ip(ctx) : PT_REGS_IP(ctx);
	event.param_second = PT_REGS_PARM2(ctx);
	bpf_map_push_elem(&events, &event, BPF_EXIST);

	return BPF_OK;
}

#ifdef HAS_KPROBE_MULTI
#define PWRU_KPROBE_TYPE "kprobe.multi"
#define PWRU_HAS_GET_FUNC_IP true
#else
#define PWRU_KPROBE_TYPE "kprobe"
#define PWRU_HAS_GET_FUNC_IP false
#endif /* HAS_KPROBE_MULTI */

#define PWRU_ADD_KPROBE(X)                                                     \
  SEC(PWRU_KPROBE_TYPE "/skb-" #X)                                             \
  int kprobe_skb_##X(struct pt_regs *ctx) {                                    \
    struct sk_buff *skb = (struct sk_buff *) PT_REGS_PARM##X(ctx);             \
    return kprobe_skb(skb, ctx, PWRU_HAS_GET_FUNC_IP);                         \
  }

PWRU_ADD_KPROBE(1)
PWRU_ADD_KPROBE(2)
PWRU_ADD_KPROBE(3)
PWRU_ADD_KPROBE(4)
PWRU_ADD_KPROBE(5)

#undef PWRU_KPROBE
#undef PWRU_HAS_GET_FUNC_IP
#undef PWRU_KPROBE_TYPE

SEC("kprobe/skb_lifetime_termination")
int kprobe_skb_lifetime_termination(struct pt_regs *ctx) {
	u64 skb = (u64) PT_REGS_PARM1(ctx);
	if (cfg->track_skb)
		bpf_map_delete_elem(&skb_addresses, &skb);

	return 0;
}

SEC("fentry/tc")
int BPF_PROG(fentry_tc, struct sk_buff *skb) {
	struct event_t event = {};

	if (!handle_everything(skb, ctx, &event))
		return BPF_OK;

	event.skb_addr = (u64) skb;
	event.addr = bpf_get_func_ip(ctx);
	bpf_map_push_elem(&events, &event, BPF_EXIST);

	return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
