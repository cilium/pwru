// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"
#include "bpf/bpf_ipv6.h"

#define PRINT_SKB_STR_SIZE    2048
#define PRINT_SHINFO_STR_SIZE PRINT_SKB_STR_SIZE

#define ETH_P_IP              0x800
#define ETH_P_IPV6            0x86dd
#define ETH_P_8021Q           0x8100

#define RTAX_MTU              2
#define SKB_DST_NOREF         1UL
#define SKB_DST_PTRMASK       ~(SKB_DST_NOREF)
#define __SKB_DST_PTR(X)      \
	((struct dst_entry *)((X) & SKB_DST_PTRMASK))

#define DST_METRICS_FLAGS     0x3UL
#define __DST_METRICS_PTR(X)  \
	((u32 *)((X) & ~DST_METRICS_FLAGS))


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

enum event_type {
	EVENT_TYPE_KPROBE = 0,
	EVENT_TYPE_TC     = 1,
	EVENT_TYPE_XDP    = 2,
};

struct event_t {
	u32 pid;
	u32 type;
	u64 addr;
	u64 caller_addr;
	u64 skb_head;
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
} skb_heads SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64); // pid_tgid
	__type(value, __u64); // struct sk_buff **
	__uint(max_entries, MAX_TRACK_SIZE);
} veth_skbs SEC(".maps");

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
	struct dst_entry *dst = __SKB_DST_PTR(BPF_CORE_READ(skb, _skb_refdst));
	if (dst) {
		u32 *metrics = __DST_METRICS_PTR(BPF_CORE_READ(dst, _metrics));
		bpf_probe_read_kernel(&meta->mtu, sizeof(meta->mtu), metrics + RTAX_MTU - 1);
		if (!meta->mtu)
			meta->mtu = BPF_CORE_READ(dst, dev, mtu);
	}
}

static __always_inline void
__set_tuple(struct tuple *tpl, void *data, u16 l3_off, bool is_ipv4) {
	u16 l4_off;

	if (is_ipv4) {
		struct iphdr *ip4 = (struct iphdr *) (data + l3_off);
		BPF_CORE_READ_INTO(&tpl->saddr, ip4, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip4, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip4, protocol);
		tpl->l3_proto = ETH_P_IP;
		l4_off = l3_off + BPF_CORE_READ_BITFIELD_PROBED(ip4, ihl) * 4;

	} else {
		struct ipv6hdr *ip6 = (struct ipv6hdr *) (data + l3_off);
		BPF_CORE_READ_INTO(&tpl->saddr, ip6, saddr);
		BPF_CORE_READ_INTO(&tpl->daddr, ip6, daddr);
		tpl->l4_proto = BPF_CORE_READ(ip6, nexthdr); // TODO: ipv6 l4 protocol
		tpl->l3_proto = ETH_P_IPV6;
		l4_off = l3_off + ipv6_hdrlen(ip6);
	}

	if (tpl->l4_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (data + l4_off);
		tpl->sport= BPF_CORE_READ(tcp, source);
		tpl->dport= BPF_CORE_READ(tcp, dest);
	} else if (tpl->l4_proto == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) (data + l4_off);
		tpl->sport= BPF_CORE_READ(udp, source);
		tpl->dport= BPF_CORE_READ(udp, dest);
	}
}

static __always_inline void
set_tuple(struct sk_buff *skb, struct tuple *tpl) {
	void *skb_head = BPF_CORE_READ(skb, head);
	u16 l3_off = BPF_CORE_READ(skb, network_header);

	struct iphdr *l3_hdr = (struct iphdr *) (skb_head + l3_off);
	u8 ip_vsn = BPF_CORE_READ_BITFIELD_PROBED(l3_hdr, version);

	if (ip_vsn !=4 && ip_vsn != 6)
		return;

	bool is_ipv4 = ip_vsn == 4;
	__set_tuple(tpl, skb_head, l3_off, is_ipv4);
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
	u64 skb_head = (u64) BPF_CORE_READ(skb, head);
	u64 stackid;

	if (cfg->track_skb_by_stackid)
		stackid = _stackid ? *_stackid : get_stackid(ctx);

	if (cfg->is_set) {
		if (cfg->track_skb && bpf_map_lookup_elem(&skb_heads, &skb_head)) {
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
		bpf_map_update_elem(&skb_heads, &skb_head, &TRUE, BPF_ANY);
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

	event.skb_head = (u64) BPF_CORE_READ(skb, head);
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
	struct sk_buff *skb = (typeof(skb)) PT_REGS_PARM1(ctx);
	u64 skb_head = (u64) BPF_CORE_READ(skb, head);

	bpf_map_delete_elem(&skb_heads, &skb_head);

	if (cfg->track_skb_by_stackid) {
		u64 stackid = get_stackid(ctx);
		bpf_map_delete_elem(&stackid_skb, &stackid);
		bpf_map_delete_elem(&skb_stackid, &skb_head);
	}

	return BPF_OK;
}

static __always_inline int
track_skb_clone(struct sk_buff *old, struct sk_buff *new) {
	u64 skb_addr_old = (u64) BPF_CORE_READ(old, head);
	u64 skb_addr_new = (u64) BPF_CORE_READ(new, head);
	if (bpf_map_lookup_elem(&skb_heads, &skb_addr_old))
		bpf_map_update_elem(&skb_heads, &skb_addr_new, &TRUE, BPF_ANY);

	return BPF_OK;
}

SEC("fexit/skb_clone")
int BPF_PROG(fexit_skb_clone, struct sk_buff *old, gfp_t mask, struct sk_buff *new) {
	if (new)
		return track_skb_clone(old, new);

	return BPF_OK;
}

SEC("fexit/skb_copy")
int BPF_PROG(fexit_skb_copy, struct sk_buff *old, gfp_t mask, struct sk_buff *new) {
	if (new)
		return track_skb_clone(old, new);

	return BPF_OK;
}

SEC("fentry/tc")
int BPF_PROG(fentry_tc, struct sk_buff *skb) {
	struct event_t event = {};

	if (!handle_everything(skb, ctx, &event, NULL))
		return BPF_OK;

	event.skb_head = (u64) BPF_CORE_READ(skb, head);
	event.addr = BPF_PROG_ADDR;
	event.type = EVENT_TYPE_TC;
	bpf_map_push_elem(&events, &event, BPF_EXIST);

	return BPF_OK;
}


static __always_inline bool
filter_xdp_netns(struct xdp_buff *xdp) {
	if (cfg->netns && BPF_CORE_READ(xdp, rxq, dev, nd_net.net, ns.inum) != cfg->netns)
		return false;

	return true;
}

static __always_inline bool
filter_xdp_ifindex(struct xdp_buff *xdp) {
	if (cfg->ifindex && BPF_CORE_READ(xdp, rxq, dev, ifindex) != cfg->ifindex)
		return false;

	return true;
}

static __always_inline bool
filter_xdp_meta(struct xdp_buff *xdp) {
	return filter_xdp_netns(xdp) && filter_xdp_ifindex(xdp);
}

static __always_inline bool
filter_xdp_pcap(struct xdp_buff *xdp) {
	void *data = (void *)(long) BPF_CORE_READ(xdp, data);
	void *data_end = (void *)(long) BPF_CORE_READ(xdp, data_end);
	return filter_pcap_ebpf_l2((void *)xdp, (void *)xdp, (void *)xdp, data, data_end);
}

static __always_inline bool
filter_xdp(struct xdp_buff *xdp) {
	return filter_xdp_pcap(xdp) && filter_xdp_meta(xdp);
}

static __always_inline void
set_xdp_meta(struct xdp_buff *xdp, struct skb_meta *meta) {
	struct net_device *dev = BPF_CORE_READ(xdp, rxq, dev);
	meta->netns = BPF_CORE_READ(dev, nd_net.net, ns.inum);
	meta->ifindex = BPF_CORE_READ(dev, ifindex);
	meta->mtu = BPF_CORE_READ(dev, mtu);
	meta->len = BPF_CORE_READ(xdp, data_end) - BPF_CORE_READ(xdp, data);
}

static __always_inline void
set_xdp_tuple(struct xdp_buff *xdp, struct tuple *tpl) {
	void *data = (void *)(long) BPF_CORE_READ(xdp, data);
	void *data_end = (void *)(long) BPF_CORE_READ(xdp, data_end);
	struct ethhdr *eth = (struct ethhdr *) data;
	u16 l3_off = sizeof(*eth);
	u16 l4_off;

	__be16 proto = BPF_CORE_READ(eth, h_proto);
	if (proto == bpf_htons(ETH_P_8021Q)) {
		struct vlan_hdr *vlan = (struct vlan_hdr *) (eth + 1);
		proto = BPF_CORE_READ(vlan, h_vlan_encapsulated_proto);
		l3_off += sizeof(*vlan);
	}
	if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6))
		return;

	bool is_ipv4 = proto == bpf_htons(ETH_P_IP);
	__set_tuple(tpl, data, l3_off, is_ipv4);
}

static __always_inline void
set_xdp_output(void *ctx, struct xdp_buff *xdp, struct event_t *event) {
	if (cfg->output_meta)
		set_xdp_meta(xdp, &event->meta);

	if (cfg->output_tuple)
		set_xdp_tuple(xdp, &event->tuple);

	if (cfg->output_stack)
		event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map, BPF_F_FAST_STACK_CMP);
}

SEC("fentry/xdp")
int BPF_PROG(fentry_xdp, struct xdp_buff *xdp) {
	u64 skb_head = (u64) BPF_CORE_READ(xdp, data_hard_start);
	struct event_t event = {};

	if (cfg->is_set) {
		if (cfg->track_skb) {
			if (!bpf_map_lookup_elem(&skb_heads, &skb_head)) {
				if (!filter_xdp(xdp))
					return BPF_OK;

				bpf_map_update_elem(&skb_heads, &skb_head, &TRUE, BPF_ANY);
			}

		} else if (!filter_xdp(xdp)) {
			return BPF_OK;
		}

		set_xdp_output(ctx, xdp, &event);
	}

	event.pid = bpf_get_current_pid_tgid() >> 32;
	event.ts = bpf_ktime_get_ns();
	event.cpu_id = bpf_get_smp_processor_id();
	event.skb_head = (u64) skb_head;
	event.addr = BPF_PROG_ADDR;
	event.type = EVENT_TYPE_XDP;
	bpf_map_push_elem(&events, &event, BPF_EXIST);

	return BPF_OK;
}

SEC("kprobe/veth_convert_skb_to_xdp_buff")
int kprobe_veth_convert_skb_to_xdp_buff(struct pt_regs *ctx) {
	struct sk_buff **pskb = (struct sk_buff **)PT_REGS_PARM3(ctx);
	struct sk_buff *skb;
	bpf_probe_read_kernel(&skb, sizeof(skb), (void *)pskb);
	u64 skb_head = (u64) BPF_CORE_READ(skb, head);
	if (bpf_map_lookup_elem(&skb_heads, &skb_head)) {
		u64 pid_tgid = bpf_get_current_pid_tgid();
		bpf_map_update_elem(&veth_skbs, &pid_tgid, &pskb, BPF_ANY);
	}
	return BPF_OK;
}

SEC("kretprobe/veth_convert_skb_to_xdp_buff")
int kretprobe_veth_convert_skb_to_xdp_buff(struct pt_regs *ctx) {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	struct sk_buff ***pskb = (struct sk_buff ***)bpf_map_lookup_elem(&veth_skbs, &pid_tgid);
	if (pskb && *pskb) {
		struct sk_buff *skb;
		bpf_probe_read_kernel(&skb, sizeof(skb), (void *)*pskb);
		u64 skb_head = (u64) BPF_CORE_READ(skb, head);
		bpf_map_update_elem(&skb_heads, &skb_head, &TRUE, BPF_ANY);
		bpf_map_delete_elem(&veth_skbs, &pid_tgid);
	}
	return BPF_OK;
}

char __license[] SEC("license") = "Dual BSD/GPL";
