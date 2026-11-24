// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */
/* Copyright (c) 2026 Authors of shirudo */

/*
 * The upatch --shirudo-upatch exports: kprobe.multi programs, one per
 * position of the sk_buff among a function's first five arguments,
 * record each sk_buff the pcap filter matches in an arena log, which the
 * events serializer drains on the target at every export. Nothing of
 * pwru runs there: shirudo loads the programs through a signed loader,
 * attaches them and reads the log back through its decoder.
 */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"
#include "bpf/bpf_endian.h"

char __license[] SEC("license") = "Dual BSD/GPL";

#if !defined(__BPF_FEATURE_ADDR_SPACE_CAST)
#error "BPF arena access requires clang address-space cast support"
#endif

#define BUILD_BUG_ON(cond)	_Static_assert(!(cond), "BUILD_BUG_ON: " #cond)
#define READ_ONCE(x)		(*(const volatile typeof(x) *)&(x))

/*
 * clang 21 emits the load-acquire and store-release of instruction set
 * v4. An older one has neither, and a fully ordered exchange or fetch
 * orders at least as much.
 */
#if defined(__BPF_FEATURE_LOAD_ACQ_STORE_REL)
#define load_acquire(p)		__atomic_load_n(p, __ATOMIC_ACQUIRE)
#define store_release(p, v)	__atomic_store_n(p, v, __ATOMIC_RELEASE)
#else
#define load_acquire(p)		__sync_fetch_and_or(p, 0)
#define store_release(p, v)	((void)__sync_lock_test_and_set(p, v))
#endif

#define __arena		__attribute__((address_space(1))) \
			__attribute__((btf_type_tag("arena")))
#define NUMA_NO_NODE	(-1)
#define MAP_TYPE_ARENA	33	/* BPF_MAP_TYPE_ARENA */

#define E2BIG		7
#define ENOMEM		12
#define EINVAL		22
#define ENOSPC		28
#define ENOENT		2

#define ETH_HLEN	14
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD
#define HEADER_UNSET	0xffff

/* The serializer ABI of shirudo's bpf/lib/serializer.h. */
#define SERIAL_MAGIC		0x5a4c5253u	/* "SRLZ" le */
#define SERIAL_VERSION		1u
#define SERIAL_F_DONE		(1u << 0)
#define SERIAL_CTX_F_PEEK	(1u << 0)
#define SERIAL_CHUNK_PAYLOAD	4032u

struct serialize_ctx {
	__u32 magic;
	__u32 version;
	__u32 flags;
	__u32 max_chunks;
	__u32 chunk_payload_size;
	__u32 page_index;
	__u64 cursor;
	__u64 invocation_id;
};

struct serial_chunk {
	__u32 magic;
	__u32 version;
	__u32 flags;
	int status;
	__u32 chunk_index;
	__u32 total_chunks;
	__u32 bytes_total;
	__u32 bytes_in_chunk;
	__u32 page_index;
	__u32 reserved;
	__u64 cursor;
	__u64 next_cursor;
	__u64 invocation_id;
	__u8 data[SERIAL_CHUNK_PAYLOAD];
};

BUILD_BUG_ON(sizeof(struct serialize_ctx) != 40);
BUILD_BUG_ON(sizeof(struct serial_chunk) != 4096);

/*
 * The serialized record, PWRU_RECORD bytes at fixed offsets, which the
 * decoder of internal/shirudo reads; the first slot of every page is a
 * header.
 */
#define PWRU_RECORD		200
#define PWRU_SERIAL_MAGIC	0x55525750u	/* "PWRU" le */
#define PWRU_SERIAL_VERSION	2
#define PWRU_FUNC_NAME_LEN	64
#define PWRU_COMM_LEN		16

/*
 * An export decodes the whole log into one OTLP log record, of at most
 * 1 MiB by default and some 700 bytes a packet.
 */
#define PWRU_LOG_CAPACITY	1024U
#define PWRU_ARENA_PAGES	128
#define PWRU_PAGE_CHUNKS	4
#define PWRU_PER_CHUNK		(SERIAL_CHUNK_PAYLOAD / PWRU_RECORD)
#define PWRU_PER_PAGE		(PWRU_PER_CHUNK * PWRU_PAGE_CHUNKS)
#define PWRU_REC_F_PRESENT	(1u << 0)
#define PWRU_HDR_F_PEEK		(1u << 0)
#define PWRU_SLOT_BUSY		0xffffffffU

static __always_inline __u32 pwru_min(__u32 a, __u32 b)
{
	return a < b ? a : b;
}

/*
 * The function's address and its second and third arguments, which the
 * decoder turns into the name and, for the functions that drop, the
 * reason.
 */
struct pwru_event {
	__u64 ts;
	__u64 skb;
	__u64 ip;
	__u64 arg2;
	__u64 arg3;
	__u32 cpu;
	__u32 pid;
	__u32 netns;
	__u32 mark;
	__u32 ifindex;
	__u32 len;
	__u16 protocol;
	__u8 l4_proto;
	__u8 tcp_flags;
	__u16 sport;
	__u16 dport;
	__u32 saddr[4];
	__u32 daddr[4];
	__u8 ip_version;
	__u8 has_ports;
	__u8 _pad[6];
	char comm[PWRU_COMM_LEN];
};

/*
 * A run claims its slot by swapping PWRU_SLOT_BUSY into the slot's
 * number, writes the event, and publishes it by storing the log's
 * sequence number with a release store; a reader that loads a matching
 * number with acquire sees the whole event. A run that took its slot
 * before the log was cleared stores the old number, which no reader
 * matches. The log may have been reused since, and the slot handed to a
 * run of the new interval: the claim, then, leaves the slot as it was.
 */
struct pwru_slot {
	__u32 seq;
	__u32 _pad;
	struct pwru_event ev;
};

struct pwru_log {
	__u32 next;
	__u32 overflow;
	__u32 seq;
	__u32 _pad;
	__u64 since_ns;
	struct pwru_slot slots[PWRU_LOG_CAPACITY];
};

enum {
	PWRU_LOG_PAGES = (sizeof(struct pwru_log) + 4095) / 4096,
};

BUILD_BUG_ON(sizeof(struct pwru_event) % 8);
BUILD_BUG_ON(PWRU_RECORD % 8);
BUILD_BUG_ON(PWRU_PER_CHUNK < 1);
BUILD_BUG_ON(2 * PWRU_LOG_PAGES > PWRU_ARENA_PAGES);

/*
 * Nothing maps the arena in userspace. One address within reach of the
 * smallest user address space of x86-64, arm64 and riscv64 keeps the
 * object the same for all three. shirudo pins no map whose name starts
 * with obs_i_.
 */
struct {
	__uint(type, MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, PWRU_ARENA_PAGES);
	__ulong(map_extra, 1ULL << 32);
} obs_i_arena SEC(".maps");

/*
 * Carries the name the serializer, the decoder and the operator use. No
 * program writes it; the serializer looks it up so that the loader,
 * which creates only the maps a program uses, creates it.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PWRU_PAGE_CHUNKS);
	__type(key, __u32);
	__type(value, struct serial_chunk);
} shirudo_ser SEC(".maps");

/* What --filter-netns and --filter-mark ask for; 0 matches every packet. */
volatile const __u32 pwru_netns;
volatile const __u32 pwru_mark;
volatile const __u32 pwru_mark_mask;

/* bpf_snprintf() takes its format from read-only memory. */
static const char pwru_func_fmt[] = "%ps";

static struct pwru_log __arena *pwru_logs[2];
static struct pwru_log __arena *pwru_active;
static struct pwru_log __arena *pwru_drain;
static __u32 pwru_lost;

void __arena *
bpf_arena_alloc_pages(void *map, void __arena *addr, __u32 page_cnt,
		      int node_id, __u64 flags) __ksym __weak;

/*
 * The verifier binds a program to the arena only through a direct
 * reference to the map: the probes, which only dereference pointers the
 * test-run program allocated, make this no-op call on a cold path.
 */
static __always_inline void pwru_arena_associate(void)
{
	bpf_arena_alloc_pages(&obs_i_arena, 0, 0, NUMA_NO_NODE, 0);
}

/*
 * The stubs pwru replaces with the pcap filter it compiled for a frame
 * from its Ethernet header on, and for a packet from its IP header on,
 * and with the --filter-skb-expr expression; libpcap.InjectFilters() and
 * pwru.InjectFilterSkbExpr() find them by name. Without a filter they let
 * every packet through.
 */
static __noinline bool
filter_pcap_ebpf_l2(void *_skb, void *__skb, void *___skb, void *data,
		    void *data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

static __noinline bool
filter_pcap_ebpf_l3(void *_skb, void *__skb, void *___skb, void *data,
		    void *data_end)
{
	return data != data_end && _skb == __skb && __skb == ___skb;
}

/*
 * The probes call it past their NULL check: an opaque skb keeps clang
 * from folding the call, and dropping the stub with it.
 */
static __noinline bool
filter_skb_expr(struct sk_buff *skb)
{
	barrier_var(skb);
	return skb != NULL;
}

/* Offsets from head; l2 and l3 HEADER_UNSET where there is none. */
struct pwru_pkt {
	unsigned char *head;
	__u32 end;
	__u16 protocol;
	__u16 l2;
	__u16 l3;
};

static __always_inline bool pwru_is_ip(__u16 protocol)
{
	return protocol == ETH_P_IP || protocol == ETH_P_IPV6;
}

/*
 * A mac_header apart from the network header is a link-layer header.
 * On the way in, __netif_receive_skb_core() sets the network header, so
 * it is still unset or stale before, and the IP header is the one right
 * after the Ethernet header. A device without a link-layer header, a
 * tunnel, sets both to the same offset, and on the way out there is no
 * mac_header before __dev_queue_xmit(). An sk_buff that is no IP packet
 * nor has a link-layer header, a netlink message, has neither. Data past
 * the linear part is not matched.
 */
static __always_inline void pwru_headers(struct sk_buff *skb,
					 struct pwru_pkt *pkt)
{
	__u16 mac = BPF_CORE_READ(skb, mac_header);
	__u16 net = BPF_CORE_READ(skb, network_header);

	pkt->head = BPF_CORE_READ(skb, head);
	pkt->end = BPF_CORE_READ(skb, tail);
	pkt->protocol = bpf_ntohs(BPF_CORE_READ(skb, protocol));
	pkt->l2 = HEADER_UNSET;
	pkt->l3 = HEADER_UNSET;
	if (mac != HEADER_UNSET && mac != net) {
		pkt->l2 = mac;
		if (net == HEADER_UNSET || net < mac)
			net = mac + ETH_HLEN;
	}
	if (net != HEADER_UNSET && pwru_is_ip(pkt->protocol))
		pkt->l3 = net;
}

static __always_inline bool pwru_match_pcap(struct sk_buff *skb,
					    const struct pwru_pkt *pkt)
{
	unsigned char *end = pkt->head + pkt->end;

	if (pkt->l2 != HEADER_UNSET)
		return filter_pcap_ebpf_l2(skb, skb, skb, pkt->head + pkt->l2,
					   end);
	if (pkt->l3 != HEADER_UNSET)
		return filter_pcap_ebpf_l3(skb, skb, skb, pkt->head + pkt->l3,
					   end);
	return false;
}

/*
 * Both pointers are __rcu; a kprobe reads them as any kernel memory, and
 * a NULL one reads as 0.
 */
static __always_inline __u32 pwru_netns_of(struct sk_buff *skb)
{
	struct net_device *dev = BPF_CORE_READ(skb, dev);
	struct net *net;

	if (dev)
		net = BPF_CORE_READ(dev, nd_net.net);
	else
		net = BPF_CORE_READ(skb, sk, __sk_common.skc_net.net);
	return net ? BPF_CORE_READ(net, ns.inum) : 0;
}

static __always_inline bool pwru_match_meta(struct sk_buff *skb)
{
	if (pwru_netns && pwru_netns_of(skb) != pwru_netns)
		return false;
	if (pwru_mark_mask &&
	    (BPF_CORE_READ(skb, mark) & pwru_mark_mask) != pwru_mark)
		return false;
	return true;
}

/*
 * Offsets into the IPv4 and IPv6 headers and the TCP or UDP header after
 * them, and their shortest lengths, as the wire lays them out.
 */
#define IP4_HLEN	20
#define IP4_FRAG_OFF	6
#define IP4_OFFSET	0x1fff
#define IP4_PROTO	9
#define IP4_SADDR	12
#define IP4_DADDR	16
#define IP6_NEXTHDR	6
#define IP6_SADDR	8
#define IP6_DADDR	24
#define IP6_HLEN	40
#define L4_SPORT	0
#define L4_DPORT	2
#define UDP_HLEN	8
#define TCP_FLAGS	13
#define TCP_HLEN	20

static __always_inline __u32 pwru_l4_hlen(__u8 l4_proto)
{
	if (l4_proto == IPPROTO_TCP)
		return TCP_HLEN;
	if (l4_proto == IPPROTO_UDP)
		return UDP_HLEN;
	return 0;
}

static __always_inline void pwru_ports(struct pwru_event *ev,
				       const unsigned char *l4, __u32 avail)
{
	__u32 hlen = pwru_l4_hlen(ev->l4_proto);
	__u8 hdr[TCP_FLAGS + 1] = {};
	__be16 port;

	if (!hlen || avail < hlen)
		return;
	if (bpf_probe_read_kernel(hdr, pwru_min(avail, sizeof(hdr)), l4))
		return;
	__builtin_memcpy(&port, &hdr[L4_SPORT], sizeof(port));
	ev->sport = bpf_ntohs(port);
	__builtin_memcpy(&port, &hdr[L4_DPORT], sizeof(port));
	ev->dport = bpf_ntohs(port);
	if (ev->l4_proto == IPPROTO_TCP)
		ev->tcp_flags = hdr[TCP_FLAGS];
	ev->has_ports = 1;
}

static __always_inline __u16 pwru_ip4_frag_offset(const __u8 *l3)
{
	__be16 frag;

	__builtin_memcpy(&frag, &l3[IP4_FRAG_OFF], sizeof(frag));
	return bpf_ntohs(frag) & IP4_OFFSET;
}

/*
 * The addresses and ports from the IP header on, and from nothing past
 * the end of the linear part: bpf_probe_read_kernel() reads on into
 * whatever memory follows it, so its success says nothing of where the
 * packet ends. An IPv6 extension header ends the walk: the next header
 * it names is recorded, without ports, as is a fragment after the first.
 */
static __always_inline void pwru_tuple(struct pwru_event *ev,
				       const struct pwru_pkt *pkt)
{
	const unsigned char *l3_ptr = pkt->head + pkt->l3;
	__u8 l3[IP6_HLEN] = {};
	__u32 avail, hlen;

	if (pkt->l3 > pkt->end || pkt->end - pkt->l3 < IP4_HLEN)
		return;
	avail = pkt->end - pkt->l3;
	if (bpf_probe_read_kernel(l3, pwru_min(avail, sizeof(l3)), l3_ptr))
		return;
	switch (l3[0] >> 4) {
	case 4:
		hlen = (l3[0] & 0xf) * 4;
		if (hlen < IP4_HLEN)
			return;
		ev->ip_version = 4;
		ev->l4_proto = l3[IP4_PROTO];
		__builtin_memcpy(ev->saddr, &l3[IP4_SADDR], 4);
		__builtin_memcpy(ev->daddr, &l3[IP4_DADDR], 4);
		if (pwru_ip4_frag_offset(l3))
			return;
		break;
	case 6:
		if (avail < IP6_HLEN)
			return;
		hlen = IP6_HLEN;
		ev->ip_version = 6;
		ev->l4_proto = l3[IP6_NEXTHDR];
		__builtin_memcpy(ev->saddr, &l3[IP6_SADDR], 16);
		__builtin_memcpy(ev->daddr, &l3[IP6_DADDR], 16);
		break;
	default:
		return;
	}
	if (hlen <= avail)
		pwru_ports(ev, l3_ptr + hlen, avail - hlen);
}

static __always_inline void pwru_fill(struct pwru_event *ev,
				      struct sk_buff *skb,
				      const struct pwru_pkt *pkt,
				      struct pt_regs *ctx)
{
	struct net_device *dev = BPF_CORE_READ(skb, dev);

	ev->ts = bpf_ktime_get_boot_ns();
	ev->skb = (__u64)skb;
	ev->ip = bpf_get_func_ip(ctx);
	ev->arg2 = PT_REGS_PARM2(ctx);
	ev->arg3 = PT_REGS_PARM3(ctx);
	ev->cpu = bpf_get_smp_processor_id();
	ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(ev->comm, sizeof(ev->comm));
	ev->mark = BPF_CORE_READ(skb, mark);
	ev->len = BPF_CORE_READ(skb, len);
	ev->protocol = pkt->protocol;
	if (dev)
		ev->ifindex = BPF_CORE_READ(dev, ifindex);
	ev->netns = pwru_netns_of(skb);
	if (pkt->l3 != HEADER_UNSET)
		pwru_tuple(ev, pkt);
}

static __always_inline void pwru_copy_in(void __arena *dst, const void *src,
					 __u32 words)
{
	__u64 __arena *d = dst;
	const __u64 *s = src;
	__u32 i;

#pragma clang loop unroll(full)
	for (i = 0; i < words; i++)
		d[i] = s[i];
}

/*
 * A full log takes nothing more from its count, which 2^32 runs between
 * two drains would otherwise wrap, handing out its slots a second time
 * within one interval.
 */
static __always_inline __u32 pwru_slot_reserve(struct pwru_log __arena *log)
{
	if (READ_ONCE(log->next) >= PWRU_LOG_CAPACITY)
		return PWRU_LOG_CAPACITY;
	return __sync_fetch_and_add(&log->next, 1);
}

/*
 * Only the run that holds a slot writes its event. The compare-and-swap
 * is a full barrier, so the log's number loaded after it is no older than
 * the one a run that published the slot before had loaded: when that run
 * was of a later interval, the number differs from seq, and the slot goes
 * back to that run's event, with a release store so that a reader
 * matching it still sees the whole event.
 */
static __always_inline bool pwru_slot_claim(struct pwru_log __arena *log,
					    struct pwru_slot __arena *slot,
					    __u32 seq)
{
	__u32 old = READ_ONCE(slot->seq);

	if (old == PWRU_SLOT_BUSY)
		return false;
	if (__sync_val_compare_and_swap(&slot->seq, old, PWRU_SLOT_BUSY) != old)
		return false;
	if (READ_ONCE(log->seq) == seq)
		return true;
	store_release(&slot->seq, old);
	return false;
}

/*
 * The sequence number is loaded with acquire before the slot is taken,
 * pairing with the release store of pwru_clear(): a clear between the
 * two makes the slot carry a number its reader does not match, never
 * another interval's.
 */
static __always_inline void pwru_record(const struct pwru_event *ev)
{
	struct pwru_log __arena *log = READ_ONCE(pwru_active);
	struct pwru_slot __arena *slot;
	__u32 seq, idx;

	if (!log) {
		pwru_arena_associate();
		return;
	}
	seq = load_acquire(&log->seq);
	idx = pwru_slot_reserve(log);
	if (idx >= PWRU_LOG_CAPACITY) {
		__sync_fetch_and_add(&log->overflow, 1);
		return;
	}
	slot = &log->slots[idx];
	if (!pwru_slot_claim(log, slot, seq))
		return;
	pwru_copy_in(&slot->ev, ev, sizeof(*ev) / 8);
	store_release(&slot->seq, seq);
}

/* Most runs see a packet the filters refuse, and end at the filters. */
static __always_inline void pwru_trace(struct sk_buff *skb,
				       struct pt_regs *ctx)
{
	struct pwru_event ev = {};
	struct pwru_pkt pkt;

	if (!skb)
		return;
	pwru_headers(skb, &pkt);
	if (!pwru_match_pcap(skb, &pkt) || !pwru_match_meta(skb) ||
	    !filter_skb_expr(skb))
		return;
	pwru_fill(&ev, skb, &pkt, ctx);
	pwru_record(&ev);
}

/*
 * The new number is stored last, with release: a run that loads it takes
 * its slot from the reset count, not from the old one, which would give
 * a slot of the new interval to two runs.
 */
static __always_inline void pwru_clear(struct pwru_log __arena *log)
{
	__u32 seq = log->seq + 1;

	if (seq == PWRU_SLOT_BUSY)
		seq = 1;
	log->next = 0;
	log->overflow = 0;
	store_release(&log->seq, seq);
}

/*
 * A run that loaded the active pointer just before the flip still
 * writes into the log being drained, which the sequence numbers make
 * safe; a drain that stopped before its last page leaves records the
 * next flip counts as lost.
 */
static __always_inline void pwru_flip(__u64 now)
{
	struct pwru_log __arena *cur = READ_ONCE(pwru_active);
	struct pwru_log __arena *spare = pwru_drain;
	__u32 n;

	if (!cur || !spare)
		return;
	if (spare->next) {
		n = spare->next;
		if (n > PWRU_LOG_CAPACITY)
			n = PWRU_LOG_CAPACITY;
		pwru_lost += n;
		pwru_clear(spare);
	}
	spare->since_ns = now;
	store_release(&pwru_active, spare);
	pwru_drain = cur;
}

static __always_inline void pwru_serial_error(int status)
{
	struct serial_chunk *chunk;
	__u32 key = 0;

	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return;
	chunk->magic = SERIAL_MAGIC;
	chunk->version = SERIAL_VERSION;
	chunk->flags = SERIAL_F_DONE;
	chunk->status = status;
	chunk->chunk_index = 0;
	chunk->total_chunks = 1;
	chunk->bytes_total = 0;
	chunk->bytes_in_chunk = 0;
}

static __always_inline struct serial_chunk *pwru_out_slot(__u32 page_slot,
							  __u32 *off_out)
{
	struct serial_chunk *chunk;
	__u32 key, off;

	barrier_var(page_slot);
	if (page_slot >= PWRU_PER_PAGE)
		return 0;
	key = page_slot / PWRU_PER_CHUNK;
	off = (page_slot % PWRU_PER_CHUNK) * PWRU_RECORD;
	barrier_var(key);
	barrier_var(off);
	if (key >= PWRU_PAGE_CHUNKS || off > SERIAL_CHUNK_PAYLOAD - PWRU_RECORD)
		return 0;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return 0;
	*off_out = off;
	return chunk;
}

static __always_inline int pwru_chunk_meta(__u32 key, __u32 flags,
					   __u32 total_chunks,
					   __u32 page_bytes,
					   const struct serialize_ctx *ctx,
					   __u64 next_cursor)
{
	struct serial_chunk *chunk;
	__u32 used;

	if (key >= total_chunks)
		return 0;
	used = page_bytes - key * SERIAL_CHUNK_PAYLOAD;
	if (used > SERIAL_CHUNK_PAYLOAD)
		used = SERIAL_CHUNK_PAYLOAD;
	chunk = bpf_map_lookup_elem(&shirudo_ser, &key);
	if (!chunk)
		return -ENOSPC;
	chunk->magic = SERIAL_MAGIC;
	chunk->version = SERIAL_VERSION;
	chunk->flags = flags;
	chunk->status = 0;
	chunk->chunk_index = key;
	chunk->total_chunks = total_chunks;
	chunk->bytes_total = page_bytes;
	chunk->bytes_in_chunk = used;
	chunk->page_index = ctx->page_index;
	chunk->reserved = 0;
	chunk->cursor = ctx->cursor;
	chunk->next_cursor = next_cursor;
	chunk->invocation_id = ctx->invocation_id;
	return 0;
}

static __always_inline __u32 pwru_used(const struct pwru_log __arena *log)
{
	return pwru_min(READ_ONCE(log->next), PWRU_LOG_CAPACITY);
}

static __always_inline int pwru_emit_header(const struct pwru_log __arena *log,
					    __u32 hdr_flags, __u64 now)
{
	struct serial_chunk *chunk;
	__u32 off;

	chunk = pwru_out_slot(0, &off);
	if (!chunk)
		return -ENOSPC;
	*(__u32 *)&chunk->data[off] = PWRU_SERIAL_MAGIC;
	*(__u16 *)&chunk->data[off + 4] = PWRU_SERIAL_VERSION;
	*(__u16 *)&chunk->data[off + 6] = PWRU_RECORD;
	*(__u32 *)&chunk->data[off + 8] = PWRU_LOG_CAPACITY;
	*(__u32 *)&chunk->data[off + 12] = hdr_flags;
	*(__u64 *)&chunk->data[off + 16] = now;
	*(__u64 *)&chunk->data[off + 24] = log->since_ns;
	*(__u32 *)&chunk->data[off + 32] = pwru_used(log);
	*(__u32 *)&chunk->data[off + 36] = log->overflow;
	*(__u32 *)&chunk->data[off + 40] = pwru_lost;
	*(__u32 *)&chunk->data[off + 44] = 0;
	return 0;
}

/*
 * The name of the function, from its address: the export resolves it
 * on the target, which pwru, building the upatch elsewhere, cannot.
 */
static __always_inline void pwru_emit_name(struct serial_chunk *chunk,
					   __u32 off, __u64 ip)
{
	__u64 args[1] = { ip };

	bpf_snprintf((char *)&chunk->data[off], PWRU_FUNC_NAME_LEN,
		     pwru_func_fmt, args, sizeof(args));
}

static __always_inline void pwru_emit_record(struct serial_chunk *chunk,
					     __u32 off, __u32 idx,
					     const struct pwru_event __arena *ev)
{
	*(__u32 *)&chunk->data[off] = idx;
	*(__u32 *)&chunk->data[off + 4] = PWRU_REC_F_PRESENT;
	*(__u64 *)&chunk->data[off + 8] = ev->ts;
	*(__u64 *)&chunk->data[off + 16] = ev->skb;
	*(__u64 *)&chunk->data[off + 24] = ev->ip;
	*(__u64 *)&chunk->data[off + 32] = ev->arg2;
	*(__u64 *)&chunk->data[off + 40] = ev->arg3;
	*(__u32 *)&chunk->data[off + 48] = ev->cpu;
	*(__u32 *)&chunk->data[off + 52] = ev->pid;
	*(__u32 *)&chunk->data[off + 56] = ev->netns;
	*(__u32 *)&chunk->data[off + 60] = ev->mark;
	*(__u32 *)&chunk->data[off + 64] = ev->ifindex;
	*(__u32 *)&chunk->data[off + 68] = ev->len;
	*(__u16 *)&chunk->data[off + 72] = ev->protocol;
	chunk->data[off + 74] = ev->l4_proto;
	chunk->data[off + 75] = ev->tcp_flags;
	*(__u16 *)&chunk->data[off + 76] = ev->sport;
	*(__u16 *)&chunk->data[off + 78] = ev->dport;
	*(__u64 *)&chunk->data[off + 80] = *(const __u64 __arena *)&ev->saddr[0];
	*(__u64 *)&chunk->data[off + 88] = *(const __u64 __arena *)&ev->saddr[2];
	*(__u64 *)&chunk->data[off + 96] = *(const __u64 __arena *)&ev->daddr[0];
	*(__u64 *)&chunk->data[off + 104] = *(const __u64 __arena *)&ev->daddr[2];
	chunk->data[off + 112] = ev->ip_version;
	chunk->data[off + 113] = ev->has_ports;
	*(__u16 *)&chunk->data[off + 114] = 0;
	*(__u32 *)&chunk->data[off + 116] = 0;
	*(__u64 *)&chunk->data[off + 120] = *(const __u64 __arena *)&ev->comm[0];
	*(__u64 *)&chunk->data[off + 128] = *(const __u64 __arena *)&ev->comm[8];
	pwru_emit_name(chunk, off + 136, ev->ip);
}

struct pwru_emit_ctx {
	struct pwru_log __arena *log;
	__u32 start;
	__u32 used;
	__u32 seq;
	__u32 output_slots;
	__u32 next;
	int ret;
};

static int pwru_emit_cb(__u32 scanned, void *data)
{
	struct pwru_emit_ctx *emit = data;
	struct pwru_slot __arena *slot;
	struct serial_chunk *chunk;
	__u32 idx, off;

	if (emit->ret)
		return 1;
	idx = emit->start + scanned;
	if (idx >= emit->used || idx >= PWRU_LOG_CAPACITY) {
		emit->next = emit->used;
		return 1;
	}
	if (emit->output_slots >= PWRU_PER_PAGE) {
		emit->next = idx;
		return 1;
	}
	emit->next = idx + 1;
	slot = &emit->log->slots[idx];
	if (load_acquire(&slot->seq) != emit->seq)
		return 0;
	chunk = pwru_out_slot(emit->output_slots, &off);
	if (!chunk) {
		emit->ret = -ENOSPC;
		return 1;
	}
	pwru_emit_record(chunk, off, idx, &slot->ev);
	emit->output_slots++;
	return 0;
}

static __always_inline int pwru_page_meta(const struct serialize_ctx *ctx,
					  __u32 flags, __u32 total_chunks,
					  __u32 page_bytes, __u64 next_cursor)
{
	__u32 i;
	int ret;

#pragma clang loop unroll(full)
	for (i = 0; i < PWRU_PAGE_CHUNKS; i++) {
		ret = pwru_chunk_meta(i, flags, total_chunks, page_bytes,
				      ctx, next_cursor);
		if (ret)
			return ret;
	}
	return 0;
}

static __always_inline struct pwru_log __arena *
pwru_serial_log(const struct serialize_ctx *ctx, bool peek, __u64 now)
{
	if (peek)
		return READ_ONCE(pwru_active);
	if (ctx->cursor == 0)
		pwru_flip(now);
	return pwru_drain;
}

static __always_inline int pwru_serialize(struct serialize_ctx *ctx)
{
	struct pwru_emit_ctx emit = {};
	struct pwru_log __arena *log;
	__u32 flags = 0, total_chunks, page_bytes;
	__u64 now = bpf_ktime_get_boot_ns();
	bool peek = ctx->flags & SERIAL_CTX_F_PEEK;
	int ret;

	if (ctx->max_chunks < PWRU_PAGE_CHUNKS)
		return -E2BIG;
	if (ctx->cursor > PWRU_LOG_CAPACITY)
		return -EINVAL;
	log = pwru_serial_log(ctx, peek, now);
	if (!log) {
		pwru_arena_associate();
		return -ENOMEM;
	}
	ret = pwru_page_meta(ctx, 0, PWRU_PAGE_CHUNKS,
			     PWRU_PAGE_CHUNKS * SERIAL_CHUNK_PAYLOAD,
			     ctx->cursor);
	if (!ret)
		ret = pwru_emit_header(log, peek ? PWRU_HDR_F_PEEK : 0, now);
	if (ret)
		return ret;

	emit.log = log;
	emit.start = (__u32)ctx->cursor;
	emit.used = pwru_used(log);
	emit.seq = READ_ONCE(log->seq);
	emit.output_slots = 1;
	emit.next = emit.used;
	if (emit.start < emit.used) {
		ret = bpf_loop(emit.used - emit.start, pwru_emit_cb, &emit, 0);
		if (ret < 0)
			return ret;
		if (emit.ret)
			return emit.ret;
	}

	if (emit.next >= emit.used) {
		flags = SERIAL_F_DONE;
		if (!peek) {
			pwru_clear(log);
			pwru_lost = 0;
		}
	}
	total_chunks = (emit.output_slots + PWRU_PER_CHUNK - 1) /
		       PWRU_PER_CHUNK;
	page_bytes = (total_chunks - 1) * SERIAL_CHUNK_PAYLOAD +
		     (emit.output_slots - (total_chunks - 1) * PWRU_PER_CHUNK) *
		     PWRU_RECORD;
	return pwru_page_meta(ctx, flags, total_chunks, page_bytes, emit.next);
}

static __always_inline bool pwru_serial_ctx_valid(const struct serialize_ctx *ctx)
{
	return ctx && ctx->magic == SERIAL_MAGIC &&
	       ctx->version == SERIAL_VERSION &&
	       ctx->chunk_payload_size == SERIAL_CHUNK_PAYLOAD;
}

SEC("syscall")
int shirudo_serialize__events(struct serialize_ctx *ctx)
{
	__u32 key = 0;
	int ret;

	if (!pwru_serial_ctx_valid(ctx))
		return -EINVAL;
	if (!bpf_map_lookup_elem(&events, &key))
		return -ENOENT;
	ret = pwru_serialize(ctx);
	if (ret)
		pwru_serial_error(ret);
	return ret;
}

/* Runs once right after attachment and allocates both logs. */
SEC("syscall")
int shirudo_test__pwru(void *ctx)
{
	struct pwru_log __arena *log;
	__u64 now = bpf_ktime_get_boot_ns();
	int i;

	if (READ_ONCE(pwru_active))
		return 0;
	for (i = 0; i < 2; i++) {
		log = bpf_arena_alloc_pages(&obs_i_arena, 0, PWRU_LOG_PAGES,
					    NUMA_NO_NODE, 0);
		if (!log)
			return -ENOMEM;
		log->next = 0;
		log->overflow = 0;
		log->seq = 1;
		log->since_ns = now;
		pwru_logs[i] = log;
	}
	pwru_drain = pwru_logs[1];
	store_release(&pwru_active, pwru_logs[0]);
	return 0;
}

/*
 * shirudo attaches each to the functions whose sk_buff is its argument
 * X, as the signed attach metadata lists them.
 */
#define PWRU_SKB_PROBE(X)						\
	SEC("kprobe.multi/skb-" #X)					\
	int pwru_skb_##X(struct pt_regs *ctx)				\
	{								\
		pwru_trace((struct sk_buff *)PT_REGS_PARM##X(ctx), ctx); \
		return 0;						\
	}

PWRU_SKB_PROBE(1)
PWRU_SKB_PROBE(2)
PWRU_SKB_PROBE(3)
PWRU_SKB_PROBE(4)
PWRU_SKB_PROBE(5)

#undef PWRU_SKB_PROBE
