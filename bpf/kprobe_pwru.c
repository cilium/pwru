// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_ipv6.h"

#define PRINT_SKB_STR_SIZE    2048
#define PRINT_SHINFO_STR_SIZE PRINT_SKB_STR_SIZE

#define ETH_P_IP              0x800
#define ETH_P_IPV6            0x86dd

const static bool TRUE = true;

volatile const static __u64 BPF_PROG_ADDR = 0;

enum {
	TRACKED_BY_FILTER = (1 << 0),
	TRACKED_BY_SKB = (1 << 1),
	TRACKED_BY_STACKID = (1 << 2),
};

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
u64 print_shinfo_id = 0;

struct event_t {
	u32 pid;
	u32 type;
	u64 addr;
	u64 caller_addr;
	u64 skb_addr;
	u64 ts;
	typeof(print_skb_id) print_skb_id;
	typeof(print_shinfo_id) print_shinfo_id;
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sk_buff *);
	__type(value, __u64);
	__uint(max_entries, MAX_TRACK_SIZE);
} skb_stackid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, struct skb *);
	__uint(max_entries, MAX_TRACK_SIZE);
} stackid_skb SEC(".maps");

struct config {
	u32 netns;
	u32 mark;
	u32 ifindex;
	u8 output_meta: 1;
	u8 output_tuple: 1;
	u8 output_skb: 1;
	u8 output_shinfo: 1;
	u8 output_stack: 1;
	u8 output_caller: 1;
	u8 output_unused: 2;
	u8 is_set: 1;
	u8 track_skb: 1;
	u8 track_skb_by_stackid: 1;
	u8 unused: 5;
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
struct print_skb_value {
	u32 len;
	char str[PRINT_SKB_STR_SIZE];
};
struct print_shinfo_value {
	u32 len;
	char str[PRINT_SHINFO_STR_SIZE];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, struct print_skb_value);
} print_skb_map SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, struct print_shinfo_value);
} print_shinfo_map SEC(".maps");
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
	struct print_skb_value *v;
	typeof(print_skb_id) id;
	long n;

	p.type_id = bpf_core_type_id_kernel(struct sk_buff);
	p.ptr = skb;
	id = __sync_fetch_and_add(&print_skb_id, 1) % 256;

	v = bpf_map_lookup_elem(&print_skb_map, (u32 *) &id);
	if (!v) {
		return;
	}

	n = bpf_snprintf_btf(v->str, PRINT_SKB_STR_SIZE, &p, sizeof(p), 0);
	if (n < 0) {
		return;
	}

	v->len = n;

	*event_id = id;
#endif
}

static __always_inline void
set_shinfo_btf(struct sk_buff *skb, typeof(print_shinfo_id) *event_id) {
#ifdef OUTPUT_SKB
	struct skb_shared_info *shinfo;
	static struct btf_ptr p = {};
	struct print_shinfo_value *v;
	typeof(print_shinfo_id) id;
	unsigned char *head;
	unsigned int end;
	long n;

        /* skb_shared_info is located at the end of skb data.
         * When CONFIG_NET_SKBUFF_DATA_USES_OFFSET is enabled, skb->end
         * is an offset from skb->head to the end of skb data. If not,
         * skb->end is a pointer to the end of skb data. For amd64 and
         * arm64 (in 64bit arch in general), CONFIG_NET_SKBUFF_DATA_USES_OFFSET
	 * is enabled by default.
         */
        head = BPF_CORE_READ(skb, head);
	end = BPF_CORE_READ(skb, end);
	shinfo = (struct skb_shared_info *)(head + end);

	p.type_id = bpf_core_type_id_kernel(struct skb_shared_info);
	p.ptr = shinfo;

	id = __sync_fetch_and_add(&print_shinfo_id, 1) % 256;

	v = bpf_map_lookup_elem(&print_shinfo_map, (u32 *) &id);
	if (!v) {
		return;
	}

	n = bpf_snprintf_btf(v->str, PRINT_SHINFO_STR_SIZE, &p, sizeof(p), 0);
	if (n < 0) {
		return;
	}

	v->len = n;

	*event_id = id;
#endif
}

static __always_inline u64
get_stackid(struct pt_regs *ctx) {
	u64 caller_fp;
	u64 fp = PT_REGS_FP(ctx);
	for (int depth = 0; depth < MAX_STACK_DEPTH; depth++) {
		if (bpf_probe_read_kernel(&caller_fp, sizeof(caller_fp), (void *)fp) < 0)
			break;

		if (caller_fp == 0)
			break;

		fp = caller_fp;
	}
	return fp;
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

	if (cfg->output_shinfo) {
		set_shinfo_btf(skb, &event->print_shinfo_id);
	}

	if (cfg->output_stack) {
		event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
	}
}

static __noinline bool
handle_everything(struct sk_buff *skb, void *ctx, struct event_t *event, u64 *_stackid) {
	u8 tracked_by;
	u64 skb_addr = (u64) skb;
	u64 stackid;

	if (cfg->track_skb_by_stackid)
		stackid = _stackid ? *_stackid : get_stackid(ctx);

	if (cfg->is_set) {
		if (cfg->track_skb && bpf_map_lookup_elem(&skb_addresses, &skb_addr)) {
			tracked_by = _stackid ? TRACKED_BY_STACKID : TRACKED_BY_SKB;
			goto cont;
		}

		if (cfg->track_skb_by_stackid && bpf_map_lookup_elem(&stackid_skb, &stackid)) {
			tracked_by = TRACKED_BY_STACKID;
			goto cont;
		}

		if (filter(skb)) {
			tracked_by = TRACKED_BY_FILTER;
			goto cont;
		}

		return false;

cont:
		set_output(ctx, skb, event);
	}

	if (cfg->track_skb && tracked_by == TRACKED_BY_FILTER) {
		bpf_map_update_elem(&skb_addresses, &skb_addr, &TRUE, BPF_ANY);
	}

	if (cfg->track_skb_by_stackid && tracked_by != TRACKED_BY_STACKID) {
		u64 *old_stackid = bpf_map_lookup_elem(&skb_stackid, &skb);
		if (old_stackid && *old_stackid != stackid) {
			bpf_map_delete_elem(&stackid_skb, old_stackid);
		}
		bpf_map_update_elem(&stackid_skb, &stackid, &skb, BPF_ANY);
		bpf_map_update_elem(&skb_stackid, &skb, &stackid, BPF_ANY);
	}

	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->ts = bpf_ktime_get_ns();
	event->cpu_id = bpf_get_smp_processor_id();

	return true;
}

static __always_inline int
kprobe_skb(struct sk_buff *skb, struct pt_regs *ctx, bool has_get_func_ip, u64 *_stackid) {
	struct event_t event = {};

	if (!handle_everything(skb, ctx, &event, _stackid))
		return BPF_OK;

	event.skb_addr = (u64) skb;
	event.addr = has_get_func_ip ? bpf_get_func_ip(ctx) : PT_REGS_IP(ctx);
	event.param_second = PT_REGS_PARM2(ctx);
	if (CFG.output_caller)
		bpf_probe_read_kernel(&event.caller_addr, sizeof(event.caller_addr), (void *)PT_REGS_SP(ctx));

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
    return kprobe_skb(skb, ctx, PWRU_HAS_GET_FUNC_IP, NULL);                         \
  }

PWRU_ADD_KPROBE(1)
PWRU_ADD_KPROBE(2)
PWRU_ADD_KPROBE(3)
PWRU_ADD_KPROBE(4)
PWRU_ADD_KPROBE(5)

SEC("kprobe/skb_by_stackid")
int kprobe_skb_by_stackid(struct pt_regs *ctx) {
	u64 stackid = get_stackid(ctx);

	struct sk_buff **skb = bpf_map_lookup_elem(&stackid_skb, &stackid);
	if (skb && *skb)
		return kprobe_skb(*skb, ctx, PWRU_HAS_GET_FUNC_IP, &stackid);

	return BPF_OK;
}

#undef PWRU_KPROBE
#undef PWRU_HAS_GET_FUNC_IP
#undef PWRU_KPROBE_TYPE

SEC("kprobe/skb_lifetime_termination")
int kprobe_skb_lifetime_termination(struct pt_regs *ctx) {
	u64 skb = (u64) PT_REGS_PARM1(ctx);

	bpf_map_delete_elem(&skb_addresses, &skb);

	if (cfg->track_skb_by_stackid) {
		u64 stackid = get_stackid(ctx);
		bpf_map_delete_elem(&stackid_skb, &stackid);
		bpf_map_delete_elem(&skb_stackid, &skb);
	}

	return BPF_OK;
}

static __always_inline int
track_skb_clone(u64 old, u64 new) {
	if (bpf_map_lookup_elem(&skb_addresses, &old))
		bpf_map_update_elem(&skb_addresses, &new, &TRUE, BPF_ANY);

	return BPF_OK;
}

SEC("fexit/skb_clone")
int BPF_PROG(fexit_skb_clone, u64 old, gfp_t mask, u64 new) {
	return track_skb_clone(old, new);
}

SEC("fexit/skb_copy")
int BPF_PROG(fexit_skb_copy, u64 old, gfp_t mask, u64 new) {
	return track_skb_clone(old, new);
}

SEC("fentry/tc")
int BPF_PROG(fentry_tc, struct sk_buff *skb) {
	struct event_t event = {};

	if (!handle_everything(skb, ctx, &event, NULL))
		return BPF_OK;

	event.skb_addr = (u64) skb;
	event.addr = BPF_PROG_ADDR;
	bpf_map_push_elem(&events, &event, BPF_EXIST);

	return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
