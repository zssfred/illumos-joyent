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
#include <libvarpd_impl.h>
#include <strings.h>

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
