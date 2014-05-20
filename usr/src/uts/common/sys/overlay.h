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

#ifndef _SYS_OVERLAY_H
#define	_SYS_OVERLAY_H

/*
 * Overlay device support
 */

#include <sys/param.h>
#include <sys/dld_ioc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	OVERLAY_IOC_CREATE	OVERLAYIOC(1)
#define	OVERLAY_IOC_DELETE	OVERLAYIOC(2)

typedef struct overlay_ioc_create {
	datalink_id_t	oic_overlay_id;
	char		oic_encap[MAXLINKNAMELEN];
} overlay_ioc_create_t;

typedef struct overlay_ioc_delete {
	datalink_id_t	oid_overlay_id;
} overlay_ioc_delete_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_OVERLAY_H */
