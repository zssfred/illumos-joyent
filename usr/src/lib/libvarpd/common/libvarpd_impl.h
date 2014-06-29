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

#ifndef _LIBVARPD_IMPL_H
#define	_LIBVARPD_IMPL_H

/*
 * varpd internal interfaces
 */

#include <libvarpd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct varpd_impl {
	int	vdi_doorfd;
} varpd_impl_t;

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_IMPL_H */
