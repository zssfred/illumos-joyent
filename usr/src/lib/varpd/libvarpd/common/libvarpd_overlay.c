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
    overlay_plugin_dest_t *destp, uint64_t *flags)
{
	overlay_targ_info_t oti;

	oti.oti_linkid = linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_INFO, &oti) != 0)
		return (errno);

	if (destp != NULL)
		*destp = oti.oti_needs;
	if (flags != NULL)
		*flags = oti.oti_flags;
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
	}

	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_ASSOCIATE, &ota) != 0)
		return (errno);

	return (0);
}

int
libvarpd_overlay_disassociate(varpd_instance_t *inst)
{
	overlay_targ_id_t otid;
	varpd_impl_t *vip = inst->vri_impl;

	otid.otid_linkid = inst->vri_linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_DISASSOCIATE, &otid) != 0)
		return (errno);
	return (0);
}

int
libvarpd_overlay_degrade(varpd_instance_t *inst)
{
	overlay_targ_id_t otid;
	varpd_impl_t *vip = inst->vri_impl;

	otid.otid_linkid = inst->vri_linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_DEGRADE, &otid) != 0)
		return (errno);
	return (0);
}

int
libvarpd_overlay_restore(varpd_instance_t *inst)
{
	overlay_targ_id_t otid;
	varpd_impl_t *vip = inst->vri_impl;

	otid.otid_linkid = inst->vri_linkid;
	if (ioctl(vip->vdi_overlayfd, OVERLAY_TARG_RESTORE, &otid) != 0)
		return (errno);
	return (0);
}

int
libvarpd_overlay_packet(varpd_impl_t *vip, overlay_targ_lookup_t *otl,
    void *buf, size_t *buflen)
{
	int ret;
	overlay_targ_pkt_t otp;

	otp.otp_linkid = UINT64_MAX;
	otp.otp_reqid = otl->otl_reqid;
	otp.otp_size = *buflen;
	otp.otp_buf = buf;

	do {
		ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_PKT, &otp);
	} while (ret != 0 && errno == EINTR);
	if (ret != 0 && errno == EFAULT)
		abort();

	if (ret == 0)
		*buflen = otp.otp_size;

	return (ret);
}

int
libvarpd_overlay_inject(varpd_impl_t *vip, overlay_targ_lookup_t *otl,
    void *buf, size_t buflen)
{
	int ret;
	overlay_targ_pkt_t otp;

	otp.otp_linkid = UINT64_MAX;
	otp.otp_reqid = otl->otl_reqid;
	otp.otp_size = buflen;
	otp.otp_buf = buf;

	do {
		ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_INJECT, &otp);
	} while (ret != 0 && errno == EINTR);
	if (ret != 0 && errno == EFAULT)
		abort();

	return (ret);
}

static void
libvarpd_overlay_lookup_reply(varpd_impl_t *vip, overlay_targ_lookup_t *otl,
    overlay_targ_resp_t *otr, int cmd)
{
	int ret;

	otr->otr_reqid = otl->otl_reqid;
	do {
		ret = ioctl(vip->vdi_overlayfd, cmd, otr);
	} while (ret != 0 && errno == EINTR);
	if (ret != 0)
		abort();
}

static void
libvarpd_overlay_lookup_handle(varpd_impl_t *vip)
{
	int ret;
	overlay_targ_lookup_t otl;
	overlay_targ_resp_t otr;
	varpd_instance_t *inst;

	ret = ioctl(vip->vdi_overlayfd, OVERLAY_TARG_LOOKUP, &otl);
	if (ret != 0 && errno != ETIME && errno != EINTR)
		abort();

	if (ret != 0)
		return;

	inst = (varpd_instance_t *)libvarpd_instance_lookup((varpd_handle_t)vip,
	    otl.otl_varpdid);
	if (inst == NULL) {
		libvarpd_overlay_lookup_reply(vip, &otl, &otr,
		    OVERLAY_TARG_DROP);
		return;
	}

	ret = inst->vri_plugin->vpp_ops->vpo_lookup(inst->vri_private, &otl,
	    &otr.otr_answer);
	if (ret == VARPD_LOOKUP_DROP) {
		libvarpd_overlay_lookup_reply(vip, &otl, &otr,
		    OVERLAY_TARG_DROP);
	} else {
		libvarpd_overlay_lookup_reply(vip, &otl, &otr,
		    OVERLAY_TARG_RESPOND);
	}
}

void
libvarpd_overlay_lookup_run(varpd_handle_t vhp)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	mutex_lock(&vip->vdi_lock);
	if (vip->vdi_lthr_quiesce == B_TRUE) {
		mutex_unlock(&vip->vdi_lock);
		return;
	}
	vip->vdi_lthr_count++;

	for (;;) {
		mutex_unlock(&vip->vdi_lock);
		libvarpd_overlay_lookup_handle(vip);
		mutex_lock(&vip->vdi_lock);
		if (vip->vdi_lthr_quiesce == B_TRUE)
			break;
	}
	assert(vip->vdi_lthr_count > 0);
	vip->vdi_lthr_count--;
	cond_signal(&vip->vdi_lthr_cv);
	mutex_unlock(&vip->vdi_lock);
}

void
libvarpd_overlay_lookup_quiesce(varpd_handle_t vhp)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	mutex_lock(&vip->vdi_lock);
	if (vip->vdi_lthr_count == 0) {
		mutex_unlock(&vip->vdi_lock);
		return;
	}
	vip->vdi_lthr_quiesce = B_TRUE;
	while (vip->vdi_lthr_count > 0)
		(void) cond_wait(&vip->vdi_lthr_cv, &vip->vdi_lock);
	vip->vdi_lthr_quiesce = B_FALSE;
	mutex_unlock(&vip->vdi_lock);
}
