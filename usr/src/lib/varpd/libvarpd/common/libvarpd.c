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
 * varpd library
 */

#include <stdlib.h>
#include <errno.h>
#include <umem.h>

#include <libvarpd_impl.h>

varpd_handle_t *
libvarpd_create(int *errp)
{
	int err;
	varpd_impl_t *vip;

	if (errp == NULL)
		errp = &err;
	vip = umem_alloc(sizeof (varpd_impl_t), UMEM_DEFAULT);
	if (vip == NULL) {
		*errp = errno;
		return (NULL);
	}

	vip->vdi_doorfd = -1;
	return ((varpd_handle_t *)vip);
}

void
libvarpd_destroy(varpd_handle_t *vhp)
{
	varpd_impl_t *vip = (varpd_impl_t *)vhp;

	umem_free(vip, sizeof (varpd_impl_t));
}
