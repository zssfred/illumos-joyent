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
    const char *, uint64_t, dladm_arg_list_t *, uint32_t);
extern dladm_status_t dladm_overlay_delete(dladm_handle_t, datalink_id_t);

typedef int (*dladm_prop_f)(dladm_handle_t, datalink_id_t,
    overlay_ioc_propinfo_t *, void *);
extern dladm_status_t dladm_overlay_walk_prop(dladm_handle_t, datalink_id_t,
    dladm_prop_f, void *arg);
extern dladm_status_t dladm_overlay_get_prop(dladm_handle_t, datalink_id_t,
    overlay_ioc_propinfo_t *, overlay_ioc_prop_t *);

extern dladm_status_t dladm_overlay_show(dladm_handle_t, datalink_id_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBDLOVERLAY_H */
