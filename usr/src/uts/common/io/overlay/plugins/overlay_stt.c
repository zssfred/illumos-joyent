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
 * STT encapsulation module
 */

#include <sys/overlay_plugin.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/stt.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
/*
 * XXX These next two header files are required to make mac_client_priv.h work
 * We should fix that.
 */
#include <sys/mac_provider.h>
#include <sys/mac_client.h>
#include <sys/mac_client_priv.h>

static const char *stt_ident = "stt";

static int
stt_o_init(void **outp)
{
	*outp = NULL;
	return (0);
}

static void
stt_o_fini(void *arg)
{
}

int
stt_o_encap(void *mh, mblk_t *mp, ovep_encap_info_t *einfop,
    mblk_t **outp)
{
	mblk_t *op;
	stt_hdr_t *hp;
	mac_header_info_t mhi;
	uint16_t vlan;
	uint32_t off;
	uint8_t flags = 0;
	ipha_t *iphp;
	ip6_t *ip6hp;

	op = allocb(STT_HDR_LEN, 0);
	if (op == NULL)
		return (ENOMEM);

	if (mac_vlan_header_info(mh, mp, &mhi) != 0)
		return (EINVAL);

	/*
	 * STT requires us to put the L4 offset into the packet, this means we
	 * actually need to care about the ethertype and process it enough to
	 * understand where to put it. However, if it's not, we're going to
	 * simply zero it.
	 */
	switch (mhi.mhi_bindsap) {
	case ETHERTYPE_IP:
		iphp = (ipha_t *)((uintptr_t)mp->b_rptr + mhi.mhi_hdrsize);

		flags |= STT_F_IPV4;
		if (iphp->ipha_protocol == IPPROTO_TCP)
			flags |= STT_F_ISTCP;
		off = mhi.mhi_hdrsize + ntohs(iphp->ipha_length);
		break;
	case ETHERTYPE_IPV6:
		ip6hp = (ip6_t *)((uintptr_t)mp->b_rptr + mhi.mhi_hdrsize);
		if (ip6hp->ip6_nxt == IPPROTO_TCP)
			flags |= STT_F_ISTCP;
		off = mhi.mhi_hdrsize + ntohs(ip6hp->ip6_plen);
		break;
	default:
		off = 0;
		flags = 0;
		break;
	}

	ASSERT((flags & STT_F_RESERVED) == 0);
	/*
	 * STT defines that the l4offset field should point to the start of the
	 * TCP or UDP payload, or at least any L4 IP/IPv6 payload. It mostly
	 * glosses over what should happen if the ethertype is not IP or IPv6.
	 * Similarly, we also have the problem that the member is only a
	 * uint8_t, which is problematic as the header sizes themselves may be
	 * larger. If we encounter a packet whose l4 offset is too large, then
	 * we will set the offset to zero instead. That seems to be the best lie
	 * that we can tell, though it's still a lie, but if we had set it to
	 * 0xff, it seems like someone would interpret that as actually valid...
	 */
	if (off > STT_L4OFF_MAX)
		off = 0;

	hp = (stt_hdr_t *)op->b_rptr;

	hp->stt_version = STT_VERSION;
	/*
	 * XXX Both of these fields require us to understand the intricacies of
	 * the packet itself. It's unclear if we should just go look at the mac
	 * header or what.
	 */
	hp->stt_flags = flags;
	hp->stt_l4off = (uint8_t)off;
	hp->stt_reserved = 0;
	hp->stt_mss = 0;

	if (mhi.mhi_istagged == B_TRUE) {
		/*
		 * The STT field is similar to a real VLAN TCI, however, the CFI
		 * bit is instead a VLAN present bit, so we must always set that
		 * to one.
		 */
		hp->stt_vlan = htons(mhi.mhi_tci | STT_VLAN_VALID);

		/*
		 * STT only allows untagged packets to go out on the wire. If we
		 * have a tagged packet, we need to remove the tag now, sigh.
		 */
		bcopy(mp->b_rptr, mp->b_rptr + 4, 12);
		mp->b_rptr += 4;
	} else {
		hp->stt_vlan = 0;
	}
	hp->stt_id = htonll(einfop->ovdi_id);
	op->b_wptr += STT_HDR_LEN;
	*outp = op;

	return (0);
}

int
stt_o_decap(void *arg, mblk_t *mp, ovep_encap_info_t *dinfop)
{
	stt_hdr_t *hp;
	uint16_t vlan;

	hp = (stt_hdr_t *)mp->b_rptr;

	dinfop->ovdi_id = ntohll(hp->stt_id);
	dinfop->ovdi_hdr_size = STT_HDR_LEN;
	vlan = ntohs(hp->stt_vlan);
	if (vlan & STT_VLAN_VALID) {
		/* XXX Should we always set the CFI bit to zero? */
		dinfop->ovdi_vlan = vlan & ~STT_VLAN_VALID;
	} else {
		dinfop->ovdi_vlan = 0;
	}

	/* XXX Ignore? */
	dinfop->ovdi_encap_type = -1;

	return (0);
}

static struct overlay_plugin_ops stt_o_ops = {
	0,
	stt_o_init,
	stt_o_fini,
	stt_o_encap,
	stt_o_decap
};

static struct modlmisc stt_modlmisc = {
	&mod_miscops,
	"STT encap plugin"
};

static struct modlinkage stt_modlinkage = {
	MODREV_1,
	&stt_modlmisc
};

int
_init(void)
{
	int err;
	overlay_plugin_register_t *ovrp;

	ovrp = overlay_plugin_alloc(OVEP_VERSION);
	if (ovrp == NULL)
		return (ENOTSUP);
	ovrp->ovep_name = stt_ident;
	ovrp->ovep_ops = &stt_o_ops;
	ovrp->ovep_id_size = STT_ID_LEN;
	ovrp->ovep_flags = OVEP_F_VLAN_TAG | OVEP_F_STRIP_TAG;
	ovrp->ovep_hdr_min = STT_HDR_LEN;
	ovrp->ovep_hdr_max = STT_HDR_LEN;
	ovrp->ovep_dest = OVERLAY_PLUGIN_D_IP | OVERLAY_PLUGIN_D_PORT;

	if ((err = overlay_plugin_register(ovrp)) == 0) {
		if ((err = mod_install(&stt_modlinkage)) != 0) {
			(void) overlay_plugin_unregister(stt_ident);
		}
	}

	overlay_plugin_free(ovrp);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&stt_modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	if ((err = overlay_plugin_unregister(stt_ident)) != 0)
		return (err);

	return (mod_remove(&stt_modlinkage));
}
