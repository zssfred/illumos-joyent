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

#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdloverlay.h>
#include <sys/dld.h>
#include <sys/overlay.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

dladm_status_t
dladm_overlay_create(dladm_handle_t handle, const char *name,
    const char *encap, uint64_t vid, uint32_t flags)
{
	int ret;
	dladm_status_t status;
	datalink_id_t linkid;
	overlay_ioc_create_t oic;

	status = dladm_create_datalink_id(handle, name, DATALINK_CLASS_OVERLAY,
	    DL_ETHER, flags, &linkid);
	if (status != DLADM_STATUS_OK)
		return (status);

	bzero(&oic, sizeof (oic));
	oic.oic_linkid = linkid;
	oic.oic_vnetid = vid;
	(void) strlcpy(oic.oic_encap, encap, MAXLINKNAMELEN);

	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_CREATE, &oic);
	if (ret != 0) {
		/* XXX We need to have private errors here */
		status = dladm_errno2status(errno);
	}

	if (status != DLADM_STATUS_OK)
		(void) dladm_destroy_datalink_id(handle, linkid, flags);

	return (status);
}

dladm_status_t
dladm_overlay_delete(dladm_handle_t handle, datalink_id_t linkid)
{
	dladm_status_t status;
	datalink_class_t class;
	overlay_ioc_delete_t oid;
	int ret;
	uint32_t flags;

	if (dladm_datalink_id2info(handle, linkid, &flags, &class, NULL,
	    NULL, 0) != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_OVERLAY)
		return (DLADM_STATUS_BADARG);

	oid.oid_linkid = linkid;
	status = DLADM_STATUS_OK;
	ret = ioctl(dladm_dld_fd(handle), OVERLAY_IOC_DELETE, &oid);
	if (ret != 0)
		status = dladm_errno2status(errno);

	if (status == DLADM_STATUS_OK)
		(void) dladm_destroy_datalink_id(handle, linkid,
		    flags);

	return (status);
}
