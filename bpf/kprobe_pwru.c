// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020-2021 Martynas Pumputis */
/* Copyright (C) 2021 Authors of Cilium */

/*
 * TODO: ipv6 l4 protocol
 * According to https://www.rfc-editor.org/rfc/rfc2460, in ipv6 header, the
 * transport layer protocol is represented by the Next Header field. However
 * ipv6 supports extension headers and recommends to place the transport layer
 * protocol at last. So if we want to parse out the transport layer protocol,
 * we have to identify all the extension headers, which is quite troublesome.
 * Currently it is assumed that there are no ipv6 extension headers.
 */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"

#define PRINT_SKB_STR_SIZE    2048

#define ETH_P_IP              0x800
#define ETH_P_IPV6            0x86dd

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
	u16 port;
	u8 output_timestamp;
	u8 output_meta;
	u8 output_tuple;
	u8 output_skb;
	u8 output_stack;
	u8 is_set;
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
	return true;
}

#define addr_empty(addr)                                \
	((addr).v6addr.d1 == 0 && (addr).v6addr.d2 == 0)


#define v6addr_equal(addr, bytes)                                                   \
	({                                                                              \
		bool is_equal;                                                              \
		u64 *u64p = (u64 *) (bytes);                                                \
		is_equal = (addr).v6addr.d1 == *u64p && (addr).v6addr.d2 == *(u64p + 1);    \
		is_equal;                                                                   \
	})

static __always_inline bool
config_tuple_empty() {
	if (!addr_empty(cfg->saddr) || !addr_empty(cfg->daddr)) {
		return false;
	}
	if (cfg->l4_proto || cfg->sport || cfg->dport || cfg->port) {
		return false;
	}
	return true;
}

/*
 * Filter by packet tuple, return true when the tuple is empty, return false
 * if one of the other fields does not match.
 */
static __always_inline bool
filter_l3_and_l4(struct sk_buff *skb) {
	if (config_tuple_empty()) {
		return true;
	}

	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);
	u16 l4_off = BPF_CORE_READ(skb, transport_header);

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);

	u16 l4_proto;

	if (cfg->ipv6 == 0 && ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;

		if (!addr_empty(cfg->saddr) && BPF_CORE_READ(ip4, saddr) != cfg->saddr.v4addr) {
			return false;
		}

		if (!addr_empty(cfg->daddr) && BPF_CORE_READ(ip4, daddr) != cfg->daddr.v4addr) {
			return false;
		}

		l4_proto = BPF_CORE_READ(ip4, protocol);
	} else if (cfg->ipv6 == 1 && ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;

		if (!addr_empty(cfg->saddr) && !v6addr_equal(cfg->saddr, BPF_CORE_READ(ip6, saddr.in6_u.u6_addr8))) {
			return false;
		}

		if (!addr_empty(cfg->daddr) && !v6addr_equal(cfg->daddr, BPF_CORE_READ(ip6, daddr.in6_u.u6_addr8))) {
			return false;
		}

		l4_proto = BPF_CORE_READ(ip6, nexthdr); // TODO: ipv6 l4 protocol
	} else {
		// currently ignore network layer protocols other than ipv4/ipv6
		return false;
	}

	if (cfg->l4_proto && l4_proto != cfg->l4_proto) {
		return false;
	}

	if (cfg->dport || cfg->sport || cfg->port) {
		u16 sport, dport;

		if (l4_proto == IPPROTO_TCP) {
			struct tcphdr *tcp = (struct tcphdr *) (skb_head + l4_off);
			sport = BPF_CORE_READ(tcp, source);
			dport = BPF_CORE_READ(tcp, dest);
		} else if (l4_proto == IPPROTO_UDP) {
			struct udphdr *udp = (struct udphdr *) (skb_head + l4_off);
			sport = BPF_CORE_READ(udp, source);
			dport = BPF_CORE_READ(udp, dest);
		} else {
			return false;
		}

		if (cfg->sport && sport != cfg->sport) {
			return false;
		}

		if (cfg->dport && dport != cfg->dport) {
			return false;
		}

		if (cfg->port && (dport != cfg->port && sport != cfg->port)) {
			return false;
		}
	}


	return true;
}

static __always_inline bool
filter(struct sk_buff *skb) {
	return filter_meta(skb) && filter_l3_and_l4(skb);
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
	u16 l4_off = BPF_CORE_READ(skb, transport_header);

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);

	if (ip_vsn == 4) {
		struct iphdr *ip4 = (struct iphdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
	} else if (ip_vsn == 6) {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) l3_hdr;
		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip6, nexthdr); // TODO: ipv6 l4 protocol
		tpl->l3_proto = ETH_P_IPV6;
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
set_output(struct pt_regs *ctx, struct sk_buff *skb, struct event_t *event) {
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

static __noinline int
handle_everything(struct sk_buff *skb, struct pt_regs *ctx, bool has_get_func_ip) {
	struct event_t event = {};

	if (cfg->is_set) {
		if (!filter(skb)) {
			return 0;
		}

		set_output(ctx, skb, &event);
	}

	event.pid = bpf_get_current_pid_tgid();
	event.addr = has_get_func_ip ? bpf_get_func_ip(ctx) : PT_REGS_IP(ctx);
	event.skb_addr = (u64) skb;
	event.ts = bpf_ktime_get_ns();
	event.cpu_id = bpf_get_smp_processor_id();
	event.param_second = PT_REGS_PARM2(ctx);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
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
    return handle_everything(skb, ctx, PWRU_HAS_GET_FUNC_IP);                  \
  }

PWRU_ADD_KPROBE(1)
PWRU_ADD_KPROBE(2)
PWRU_ADD_KPROBE(3)
PWRU_ADD_KPROBE(4)
PWRU_ADD_KPROBE(5)

#undef PWRU_KPROBE
#undef PWRU_HAS_GET_FUNC_IP
#undef PWRU_KPROBE_TYPE

char __license[] SEC("license") = "GPL";
