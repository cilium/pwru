#include "vmlinux.h"
#include "bpf/bpf_core_read.h"

#define IPV6_MAX_HEADERS 4

#define NEXTHDR_HOP             0       /* Hop-by-hop option header. */
#define NEXTHDR_TCP             6       /* TCP segment. */
#define NEXTHDR_UDP             17      /* UDP message. */
#define NEXTHDR_IPV6            41      /* IPv6 in IPv6 */
#define NEXTHDR_ROUTING         43      /* Routing header. */
#define NEXTHDR_FRAGMENT        44      /* Fragmentation/reassembly header. */
#define NEXTHDR_GRE             47      /* GRE header. */
#define NEXTHDR_ESP             50      /* Encapsulating security payload. */
#define NEXTHDR_AUTH            51      /* Authentication header. */
#define NEXTHDR_ICMP            58      /* ICMP for IPv6. */
#define NEXTHDR_NONE            59      /* No next header */
#define NEXTHDR_DEST            60      /* Destination options header. */
#define NEXTHDR_SCTP            132     /* SCTP message. */
#define NEXTHDR_MOBILITY        135     /* Mobility header. */

#define NEXTHDR_MAX             255

static __always_inline int ipv6_optlen(const struct ipv6_opt_hdr *opthdr)
{
	return (BPF_CORE_READ(opthdr, hdrlen) + 1) << 3;
}

static __always_inline int ipv6_authlen(const struct ipv6_opt_hdr *opthdr)
{
	return (BPF_CORE_READ(opthdr, hdrlen) + 2) << 2;
}

static __always_inline int ipv6_hdrlen(struct ipv6hdr *ip6)
{
	int i, len = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr *opthdr;
	u8 nexthdr = BPF_CORE_READ(ip6, nexthdr);

#pragma unroll
	for (i = 0; i < IPV6_MAX_HEADERS; i++) {
		switch (nexthdr) {
		case NEXTHDR_NONE:
			return 0;

		case NEXTHDR_FRAGMENT:
			return 0;

		case NEXTHDR_HOP:
		case NEXTHDR_ROUTING:
		case NEXTHDR_AUTH:
		case NEXTHDR_DEST:
			opthdr = (struct ipv6_opt_hdr *)ip6 + len;

			if (nexthdr == NEXTHDR_AUTH)
				len += ipv6_authlen(opthdr);
			else
				len += ipv6_optlen(opthdr);

			BPF_CORE_READ_INTO(&nexthdr, opthdr, nexthdr);
			break;

		default:
			return len;
		}
	}

	/* Reached limit of supported extension headers */
	return 0;
}

