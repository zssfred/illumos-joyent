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

#ifndef _LIBDLOVERLAY_H
#define	_LIBDLOVERLAY_H

/*
 * libdladm Overlay device routines
 */

#include <libdladm.h>
#include <libdladm_impl.h>
#include <sys/overlay.h>

#ifdef __cplusplus
extern "C" {
#endif

extern dladm_status_t dladm_overlay_create(dladm_handle_t, const char *,
    const char *, const char *, uint64_t, dladm_arg_list_t *, uint32_t);
extern dladm_status_t dladm_overlay_delete(dladm_handle_t, datalink_id_t);

#define	DLADM_OVERLAY_PROP_SIZEMAX	256
#define	DLADM_OVERLAY_PROP_NAMELEN	32

typedef struct __dladm_overlay_propinfo *dladm_overlay_propinfo_handle_t;

extern dladm_status_t dladm_overlay_prop_info(dladm_overlay_propinfo_handle_t,
    const char **, uint_t *, uint_t *, const void **, uint32_t *,
    const mac_propval_range_t **);
extern dladm_status_t dladm_overlay_get_prop(dladm_handle_t, datalink_id_t,
    dladm_overlay_propinfo_handle_t, void *buf, size_t *bufsize);

typedef int (*dladm_overlay_prop_f)(dladm_handle_t, datalink_id_t,
    dladm_overlay_propinfo_handle_t, void *);
extern dladm_status_t dladm_overlay_walk_prop(dladm_handle_t, datalink_id_t,
    dladm_overlay_prop_f, void *arg);

/*
 * The following is the likely API for setting a property.
 */
#if 0
extern dladm_status_t dladm_overlay_prop_lookup(dladm_handle_t, datalink_id_t,
    const char *, dladm_overlay_propinfo_handle_t *);
extern void dladm_overlay_prop_handle_free(dladm_handle_t, datalink_id_t,
    dladm_overlay_propinfo_handle_t *);
extern dladm_status_t dladm_overlay_set_prop(dladm_handle_t, datalink_id_t,
    dladm_propinfo_handle_t, void *buf, size_t *bufsize);
extern dladm_status_t dladm_overlay_str_to_buf(dladm_handle_t, datalink_id_t,
    dladm_overlay_propinfo_handle_t *, const char *, void *, size_t *);
extern dladm_status_t dladm_overlay_buf_to_str(dladm_handle_t, datalink_id_t,
    dladm_overlay_propinfo_handle_t *, const void *, const size_t, char *,
    size_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LIBDLOVERLAY_H */
