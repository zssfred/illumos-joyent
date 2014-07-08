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

#ifndef _LIBVARPD_CLIENT_H
#define	_LIBVARPD_CLIENT_H

/*
 * varpd interfaces
 */

#include <sys/types.h>
#include <stdint.h>
#include <sys/mac.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct __varpd_client_handle *varpd_client_handle_t;
typedef struct __varpd_client_prop_handle *varpd_client_prop_handle_t;

/*
 * This should stay in sync with OVERLAY_PROP_*
 */
#define	LIBVARPD_PROP_SIZEMAX	256
#define	LIBVARPD_PROP_NAMELEN	32

extern int libvarpd_c_create(varpd_client_handle_t *, const char *);
extern int libvarpd_c_destroy(varpd_client_handle_t);
extern int libvarpd_c_instance_create(varpd_client_handle_t, datalink_id_t,
    const char *, uint64_t *);
extern int libvarpd_c_instance_activate(varpd_client_handle_t, uint64_t);
extern int libvarpd_c_instance_destroy(varpd_client_handle_t, uint64_t);

extern int libvarpd_c_prop_nprops(varpd_client_handle_t, uint64_t, uint_t *);
extern int libvarpd_c_prop_handle_alloc(varpd_client_handle_t, uint64_t,
    varpd_client_prop_handle_t *);
extern void libvarpd_c_prop_handle_free(varpd_client_prop_handle_t);
extern int libvarpd_c_prop_info_fill(varpd_client_prop_handle_t, uint_t);
extern int libvarpd_c_prop_info_fill_by_name(varpd_client_prop_handle_t,
    const char *);
extern int libvarpd_c_prop_info(varpd_client_prop_handle_t, const char **,
    uint_t *, uint_t *, const void **, uint32_t *,
    const mac_propval_range_t **);
extern int libvarpd_c_prop_get(varpd_client_prop_handle_t, void *, uint32_t *);
extern int libvarpd_c_prop_set(varpd_client_prop_handle_t, const void *,
    uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_CLIENT_H */
