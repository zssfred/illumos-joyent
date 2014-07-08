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
 * Copyright (c) 2014 Joyent, Inc.
 */

/*
 * Interactions with /dev/overlay
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stropts.h>
#include <strings.h>

#include <libvarpd_impl.h>
#include <sys/overlay_target.h>

#define	OVERLAY_PATH	"/dev/overlay"

int
libvarpd_overlay_init(varpd_impl_t *vip)
{
	vip->vdi_overlayfd = open(OVERLAY_PATH, O_RDWR);
	if (vip->vdi_overlayfd == -1)
		return (errno);
	return (0);
}

void
libvarpd_overlay_fini(varpd_impl_t *vip)
{
	assert(vip->vdi_overlayfd > 0);
	if (close(vip->vdi_overlayfd) != 0)
		abort();
}

int
libvarpd_overlay_info(varpd_impl_t *vip, datalink_id_t linkid,
    overlay_plugin_dest_t *destp)
{
	overlay_targ_info_t oti;

	oti.oti_linkid = linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_INFO, &oti) != 0)
		return (errno);

	*destp = oti.oti_needs;
	return (0);
}

int
libvarpd_overlay_associate(varpd_instance_t *inst)
{
	overlay_targ_associate_t ota;
	varpd_impl_t *vip = inst->vri_impl;

	bzero(&ota, sizeof (overlay_targ_associate_t));
	ota.ota_linkid = inst->vri_linkid;
	ota.ota_mode = inst->vri_mode;
	ota.ota_id = inst->vri_id;
	ota.ota_provides = inst->vri_dest;

	if (ota.ota_mode == OVERLAY_TARGET_POINT) {
		int ret;
		ret = inst->vri_plugin->vpp_ops->vpo_lookup(inst->vri_private,
		    NULL, &ota.ota_point);
		if (ret != 0)
			return (ret);

		if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_ASSOCIATE,
		    &ota) != 0)
			return (errno);
	}

	return (0);
}
