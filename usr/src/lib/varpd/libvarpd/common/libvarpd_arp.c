/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Common routines for implmeenting proxy arp
 */

#include <sys/types.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <netinet/dhcp.h>
#include <libvarpd_impl.h>
#include <sys/vlan.h>
#include <strings.h>
#include <assert.h>

#define	IPV6_VERSION	6

int
libvarpd_plugin_proxy_arp(varpd_provider_handle_t hdl,
    overlay_targ_lookup_t *otl)
{
	char buf[1500];
	size_t bsize = sizeof (buf);
	varpd_instance_t *inst = (varpd_instance_t *)hdl;
	struct ether_arp *ea;
	struct sockaddr_storage s;
	struct sockaddr_in *ip;
	struct ether_header *ether;
	uint8_t lookup[ETHERADDRL];

	if (otl->otl_sap != ETHERTYPE_ARP)
		return (VARPD_LOOKUP_DROP);

	/*
	 * An ARP packet should not be very large because it's definited to only
	 * be allowed to have a single entry at a given time. But our data must
	 * be at least as large as an ether_arp and our header must be at least
	 * as large as a standard ethernet header.
	 */
	if (otl->otl_hdrsize + otl->otl_pktsize > bsize ||
	    otl->otl_pktsize < sizeof (struct ether_arp) ||
	    otl->otl_hdrsize < sizeof (struct ether_header))
		return (VARPD_LOOKUP_DROP);

	if (libvarpd_overlay_packet(inst->vri_impl, otl, buf, &bsize) != 0)
		return (VARPD_LOOKUP_DROP);

	ea = (void *)((uintptr_t)buf + (uintptr_t)otl->otl_hdrsize);

	/*
	 * Make sure it matches something that we know about.
	 */
	if (ntohs(ea->ea_hdr.ar_hrd) != ARPHRD_ETHER ||
	    ntohs(ea->ea_hdr.ar_pro) != ETHERTYPE_IP ||
	    ea->ea_hdr.ar_hln != ETHERADDRL ||
	    ea->ea_hdr.ar_pln != sizeof (ea->arp_spa) ||
	    ntohs(ea->ea_hdr.ar_op) != ARPOP_REQUEST)
		return (VARPD_LOOKUP_DROP);

	/*
	 * Now that we've verified that our data is sane, see if we're doing a
	 * gratuitous arp and if so, drop it. Otherwise, we may end up
	 * triggering duplicate address detection.
	 */
	if (bcmp(ea->arp_spa, ea->arp_tpa, sizeof (ea->arp_spa)) == 0)
		return (VARPD_LOOKUP_DROP);

	bzero(&s, sizeof (struct sockaddr_storage));
	ip = (struct sockaddr_in *)&s;
	ip->sin_family = AF_INET;
	bcopy(ea->arp_tpa, &ip->sin_addr, sizeof (ea->arp_tpa));

	if (inst->vri_plugin->vpp_ops->vpo_arp(inst->vri_private,
	    VARPD_ARP_ETHERNET, (struct sockaddr *)ip, lookup) != 0)
		return (VARPD_LOOKUP_DROP);

	/*
	 * Modify our packet in place for a reply. We need to swap around the
	 * sender and target addresses.
	 */
	ea->ea_hdr.ar_op = htons(ARPOP_REPLY);
	bcopy(ea->arp_sha, ea->arp_tha, ETHERADDRL);
	bcopy(lookup, ea->arp_sha, ETHERADDRL);
	bcopy(ea->arp_spa, &ip->sin_addr, sizeof (ea->arp_spa));
	bcopy(ea->arp_tpa, ea->arp_spa, sizeof (ea->arp_spa));
	bcopy(&ip->sin_addr, ea->arp_tpa, sizeof (ea->arp_spa));

	/*
	 * Finally go ahead and fix up the mac header and reply to the sender
	 * explicitly.
	 */
	ether = (struct ether_header *)buf;
	bcopy(&ether->ether_shost, &ether->ether_dhost, ETHERADDRL);
	bcopy(lookup, &ether->ether_shost, ETHERADDRL);

	(void) libvarpd_overlay_inject(inst->vri_impl, otl, buf, bsize);

	return (VARPD_LOOKUP_DROP);
}

static uint16_t
libvarpd_icmpv6_checksum(const ip6_t *v6hdr, const uint16_t *buf, uint16_t mlen)
{
	int i;
	uint16_t *v;
	uint32_t sum = 0;

	assert(mlen % 2 == 0);
	v = (uint16_t *)&v6hdr->ip6_src;
	for (i = 0; i < sizeof (struct in6_addr); i += 2, v++)
		sum += *v;
	v = (uint16_t *)&v6hdr->ip6_dst;
	for (i = 0; i < sizeof (struct in6_addr); i += 2, v++)
		sum += *v;
	sum += htons(mlen);
#ifdef _BIG_ENDIAN
	sum += IPPROTO_ICMPV6;
#else
	sum += IPPROTO_ICMPV6 << 8;
#endif	/* _BIG_ENDIAN */

	for (i = 0; i < mlen; i += 2, buf++)
		sum += *buf;

	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);

	return (sum & 0xffff);
}

/*
 * Proxying NDP is much more involved than proxying ARP. For starters, NDP
 * neighbor solicitations are implemented in terms of IPv6 ICMP as opposed to
 * its own Ethertype. Therefore, we're going to have to grab a packet if it's a
 * multicast packet and then determine if we actually want to do anything with
 * it.
 */
int
libvarpd_plugin_proxy_ndp(varpd_provider_handle_t hdl,
    overlay_targ_lookup_t *otl)
{
	char buf[ETHERMAX + VLAN_TAGSZ];
	char resp[ETHERMAX + VLAN_TAGSZ];
	ip6_t *v6hdr;
	nd_neighbor_solicit_t *ns;
	nd_neighbor_advert_t *na;
	nd_opt_hdr_t *opt;
	uint8_t lookup[ETHERADDRL];
	struct sockaddr_storage s;
	struct sockaddr_in6 *s6;
	struct ether_header *ether;
	ssize_t plen, roff;

	uint8_t *eth = NULL;
	size_t bsize = sizeof (buf);
	varpd_instance_t *inst = (varpd_instance_t *)hdl;

	if (otl->otl_dstaddr[0] != 0x33 ||
	    otl->otl_dstaddr[1] != 0x33)
		return (VARPD_LOOKUP_DROP);

	/*
	 * If we have more than a standard frame size for the ICMP neighbor
	 * solicitation, drop it. Similarly if there isn't enough data present
	 * for us, drop it.
	 */
	if (otl->otl_hdrsize + otl->otl_pktsize > bsize)
		return (VARPD_LOOKUP_DROP);

	if (otl->otl_pktsize < sizeof (ip6_t) + sizeof (nd_neighbor_solicit_t))
		return (VARPD_LOOKUP_DROP);

	if (libvarpd_overlay_packet(inst->vri_impl, otl, buf, &bsize) != 0)
		return (VARPD_LOOKUP_DROP);

	bsize -= otl->otl_hdrsize;
	assert(bsize > sizeof (ip6_t));

	v6hdr = (ip6_t *)(buf + otl->otl_hdrsize);
	if (((v6hdr->ip6_vfc & 0xf0) >> 4) != IPV6_VERSION)
		return (VARPD_LOOKUP_DROP);

	if (v6hdr->ip6_nxt != IPPROTO_ICMPV6)
		return (VARPD_LOOKUP_DROP);

	/*
	 * In addition to getting these requests on the multicast address for
	 * node solicitation, we may also end up getting them on a generic
	 * multicast address due to timeouts or other choices by various OSes.
	 * We should fairly liberal and accept both, even though the standard
	 * wants them to a solicitation address.
	 */
	if (!IN6_IS_ADDR_MC_SOLICITEDNODE(&v6hdr->ip6_dst) &&
	    !IN6_IS_ADDR_MC_LINKLOCAL(&v6hdr->ip6_dst))
		return (VARPD_LOOKUP_DROP);
	bsize -= sizeof (ip6_t);
	plen = ntohs(v6hdr->ip6_plen);
	if (bsize < plen)
		return (VARPD_LOOKUP_DROP);

	/*
	 * Now we know that this is an ICMPv6 request targetting the right
	 * IPv6 multicast prefix. Let's go through and verify that ICMPv6
	 * indicates that we have the real thing and ensure that per RFC 4861
	 * the target address is not a multicast address. Further, because this
	 * is a multicast on Ethernet, we must have a source link-layer address.
	 *
	 * XXX We should probably validate the checksum here...
	 */
	ns = (nd_neighbor_solicit_t *)(buf + otl->otl_hdrsize + sizeof (ip6_t));
	if (ns->nd_ns_type != ND_NEIGHBOR_SOLICIT && ns->nd_ns_code != 0)
		return (VARPD_LOOKUP_DROP);

	if (IN6_IS_ADDR_MULTICAST(&ns->nd_ns_target) ||
	    IN6_IS_ADDR_V4MAPPED(&ns->nd_ns_target) ||
	    IN6_IS_ADDR_LOOPBACK(&ns->nd_ns_target))
		return (VARPD_LOOKUP_DROP);
	plen -= sizeof (nd_neighbor_solicit_t);
	opt = (nd_opt_hdr_t *)(ns+1);
	while (plen >= sizeof (struct nd_opt_hdr)) {
		/* If we have an option with no lenght, that's clear bogus */
		if (opt->nd_opt_len == 0)
			return (VARPD_LOOKUP_DROP);
		if (opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR) {
			eth = (uint8_t *)((uintptr_t)opt +
			    sizeof (nd_opt_hdr_t));
		}
		plen -= opt->nd_opt_len * 8;
		opt = (nd_opt_hdr_t *)((uintptr_t)opt +
		    opt->nd_opt_len * 8);
	}

	if (eth == NULL)
		return (VARPD_LOOKUP_DROP);

	bzero(&s, sizeof (struct sockaddr_storage));
	s6 = (struct sockaddr_in6 *)&s;
	s6->sin6_family = AF_INET6;
	bcopy(&ns->nd_ns_target, &s6->sin6_addr, sizeof (s6->sin6_addr));

	if (inst->vri_plugin->vpp_ops->vpo_arp(inst->vri_private,
	    VARPD_ARP_ETHERNET, (struct sockaddr *)s6, lookup) != 0)
		return (VARPD_LOOKUP_DROP);

	/*
	 * Now we need to assemble an RA as a response. Unlike with arp, we opt
	 * to use a new packet just to make things a bit simpler saner here.
	 */
	roff = 0;
	bcopy(buf, resp, otl->otl_hdrsize);
	ether = (struct ether_header *)resp;
	bcopy(&ether->ether_shost, &ether->ether_dhost, ETHERADDRL);
	bcopy(lookup, &ether->ether_shost, ETHERADDRL);
	roff += otl->otl_hdrsize;
	bcopy(v6hdr, resp + roff, sizeof (ip6_t));
	v6hdr = (ip6_t *)(resp + roff);
	bcopy(&v6hdr->ip6_src, &v6hdr->ip6_dst, sizeof (struct in6_addr));
	bcopy(&ns->nd_ns_target, &v6hdr->ip6_src, sizeof (struct in6_addr));
	roff += sizeof (ip6_t);
	na = (nd_neighbor_advert_t *)(resp + roff);
	na->nd_na_type = ND_NEIGHBOR_ADVERT;
	na->nd_na_code = 0;
	/*
	 * RFC 4443 defines that we should set the checksum to zero before we
	 * calculate the checksumat we should set the checksum to zero before we
	 * calculate it.
	 */
	na->nd_na_cksum = 0;
	/*
	 * Nota bene, the header <netinet/icmp6.h> has already transformed this
	 * into the appropriate host order. Don't use htonl.
	 */
	na->nd_na_flags_reserved = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
	bcopy(&ns->nd_ns_target, &na->nd_na_target, sizeof (struct in6_addr));
	roff += sizeof (nd_neighbor_advert_t);

	opt = (nd_opt_hdr_t *)(resp + roff);
	opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	opt->nd_opt_len = 1;
	roff += sizeof (nd_opt_hdr_t);
	bcopy(lookup, resp + roff, ETHERADDRL);
	roff += ETHERADDRL;

	/*
	 * Now that we've filled in the packet, go back and compute the checksum
	 * and fill in the IPv6 payload size.
	 */
	v6hdr->ip6_plen = htons(roff - sizeof (ip6_t) - otl->otl_hdrsize);
	na->nd_na_cksum = ~libvarpd_icmpv6_checksum(v6hdr, (uint16_t *)na,
	    ntohs(v6hdr->ip6_plen)) & 0xffff;

	(void) libvarpd_overlay_inject(inst->vri_impl, otl, resp, roff);

	return (VARPD_LOOKUP_DROP);
}

int
libvarpd_plugin_proxy_dhcp(varpd_provider_handle_t hdl,
    overlay_targ_lookup_t *otl, const uint8_t *naddr)
{
	char buf[1500];
	size_t bsize = sizeof (buf);
	varpd_instance_t *inst = (varpd_instance_t *)hdl;
	struct ether_header *ether;
	struct ip *ip;
	struct udphdr *udp;
	static const uint8_t bcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff,
	    0xff };

	if (otl->otl_sap != ETHERTYPE_IP)
		return (VARPD_LOOKUP_DROP);

	if (bcmp(otl->otl_dstaddr, bcast_mac, ETHERADDRL) != 0)
		return (VARPD_LOOKUP_DROP);

	if (otl->otl_hdrsize + otl->otl_pktsize > bsize ||
	    otl->otl_pktsize < sizeof (struct ip) + sizeof (struct udphdr) +
	    sizeof (struct dhcp) ||
	    otl->otl_hdrsize < sizeof (struct ether_header))
		return (VARPD_LOOKUP_DROP);

	if (libvarpd_overlay_packet(inst->vri_impl, otl, buf, &bsize) != 0)
		return (VARPD_LOOKUP_DROP);

	if (bsize != otl->otl_hdrsize + otl->otl_pktsize)
		return (VARPD_LOOKUP_DROP);

	ether = (struct ether_header *)buf;
	ip = (struct ip *)(buf + otl->otl_hdrsize);

	if (ip->ip_v != IPVERSION && ip->ip_p != IPPROTO_UDP)
		return (VARPD_LOOKUP_DROP);

	if (otl->otl_hdrsize + ip->ip_hl * 4 + sizeof (struct udphdr) > bsize)
		return (VARPD_LOOKUP_DROP);

	udp = (struct udphdr *)(buf + otl->otl_hdrsize + ip->ip_hl * 4);

	if (ntohs(udp->uh_sport) != IPPORT_BOOTPC ||
	    ntohs(udp->uh_dport) != IPPORT_BOOTPS)
		return (VARPD_LOOKUP_DROP);

	bcopy(naddr, &ether->ether_dhost, ETHERADDRL);

	(void) libvarpd_overlay_resend(inst->vri_impl, otl, buf, bsize);

	return (VARPD_LOOKUP_DROP);
}
