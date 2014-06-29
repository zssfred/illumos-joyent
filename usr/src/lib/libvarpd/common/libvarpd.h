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

#ifndef _LIBVARPD_H
#define	_LIBVARPD_H

/*
 * varpd interfaces
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __varpd_handle *varpd_handle_t;

extern varpd_handle_t *libvarpd_create(int *);
extern void libvarpd_destroy(varpd_handle_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_H */
