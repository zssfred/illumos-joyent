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
 * VXLAN encapsulation module
 *
 *
 * The VXLAN header looks as follows in network byte order:
 *
 * |0        3| 4 |5                     31|
 * +----------+---+------------------------+
 * | Reserved | I | Reserved               |
 * +---------------------------------------+
 * | Virtual Network ID         | Reserved |
 * +----------------------------+----------+
 * |0                         23|24      31|
 * END CSTYLED
 *
 * All reserved values must be 0. The I bit must be 1. We call the top
 * word the VXLAN magic field for the time being. The second word is
 * definitely not the most friendly way to operate. Specifically, the ID
 * is a 24-bit big endian value, but we have to make sure not to use the
 * lower word.
 */

#include <sys/overlay_plugin.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/byteorder.h>
#include <sys/vxlan.h>

static const char *vxlan_ident = "vxlan";

/*
 * XXX Stats?
 */
int
vxlan_o_encap(mac_handle_t arg, mblk_t *mp, ovep_encap_info_t *einfop,
    mblk_t **outp)
{
	mblk_t *ob;
	vxlan_hdr_t *vxh;

	ASSERT(einfop->ovdi_id < (1 << 24));

	/*
	 * XXX We probably want a good way to cache and handle the allocation
	 * and destruction of these message blocks.
	 */
	ob = allocb(VXLAN_HDR_LEN, 0);
	if (ob == NULL)
		return (ENOMEM);



	vxh = (vxlan_hdr_t *)ob->b_rptr;
	vxh->vxlan_id = htonl((uint32_t)einfop->ovdi_id << VXLAN_ID_SHIFT);
	ob->b_wptr += VXLAN_HDR_LEN;
	*outp = ob;

	return (0);
}

/* XXX Stats */
int
vxlan_o_decap(mac_handle_t arg, mblk_t *mp, ovep_encap_info_t *dinfop)
{
	vxlan_hdr_t *vxh;

	vxh = (vxlan_hdr_t *)mp->b_rptr;
	if ((ntohl(vxh->vxlan_magic) & VXLAN_MAGIC) == 0)
		return (EINVAL);

	dinfop->ovdi_id = ntohl(vxh->vxlan_id >> VXLAN_ID_SHIFT);
	dinfop->ovdi_hdr_size = VXLAN_HDR_LEN;
	/* XXX Probably don't need these fields in the long run */
	dinfop->ovdi_encap_type = -1;
	dinfop->ovdi_vlan = -1;

	return (0);
}

static struct overlay_plugin_ops vxlan_o_ops = {
	0,
	vxlan_o_encap,
	vxlan_o_decap
};

static struct modlmisc vxlan_modlmisc = {
	&mod_miscops,
	"VXLAN encap plugin"
};

static struct modlinkage vxlan_modlinkage = {
	MODREV_1,
	&vxlan_modlmisc
};

int
_init(void)
{
	int err;
	overlay_plugin_register_t *ovrp;

	ovrp = overlay_plugin_alloc(OVEP_VERSION);
	if (ovrp == NULL)
		return (ENOTSUP);
	ovrp->ovep_name = vxlan_ident;
	ovrp->ovep_ops = &vxlan_o_ops;
	ovrp->ovep_id_size = VXLAN_ID_LEN;
	ovrp->ovep_flags = OVEP_F_VLAN_TAG;
	ovrp->ovep_hdr_min = VXLAN_HDR_LEN;
	ovrp->ovep_hdr_max = VXLAN_HDR_LEN;
	ovrp->ovep_media = OVERLAY_PLUGIN_M_UDP;

	if ((err = overlay_plugin_register(ovrp)) == 0) {
		if ((err = mod_install(&vxlan_modlinkage)) != 0) {
			(void) overlay_plugin_unregister(vxlan_ident);
		}
	}

	overlay_plugin_free(ovrp);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vxlan_modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	if ((err = overlay_plugin_unregister(vxlan_ident)) != 0)
		return (err);

	return (mod_remove(&vxlan_modlinkage));
}
