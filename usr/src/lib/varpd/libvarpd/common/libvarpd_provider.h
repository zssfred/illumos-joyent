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

#ifndef _LIBVARPD_PROVIDER_H
#define	_LIBVARPD_PROVIDER_H

/*
 * varpd provider interface
 *
 * This header file defines all the structures and functions that a given plugin
 * should register.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX Should this be opaque?
 */
typedef struct message_header message_header_t;
typedef struct __varpd_prop_handle *varpd_prop_handle_t;

/*
 * Create a new instance of a plugin.
 */
typedef int (*varpd_plugin_create_f)(void **, overlay_plugin_dest_t);

/*
 * Upon the return of this, the lookup function will be called.
 */
typedef int (*varpd_plugin_start_f)(void *);

/*
 * Upon the entry of this function, the lookup function will not be called.
 */
typedef int (*varpd_plugin_stop_f)(void *);

/*
 * Destroy an instance of a plugin.
 */
typedef void (*varpd_plugin_destroy_f)(void *);

/*
 * Look up the destination specified by the message_header_t and store it in the
 * overlay_target_point_t. If the value of the message_header_t is NULL, then
 * that is our way of asking for a default.
 *
 * Multiple threads may call this function in parallel.
 */
typedef int (*varpd_plugin_lookup_f)(void *, message_header_t *,
    overlay_target_point_t *);

/*
 * The following four functions all revolve around properties that exist for
 * varpd. A plugin should strive to have a uniform set of properties that exist,
 * however a given plugin may not always support every property. For example, in
 * a vxlan world, the target IP address and port are both required; however,
 * there are other encapsulation protocols which only require an IP address, or
 * maybe require something else.
 */

/*
 * Obtain a total number of properties.
 */
typedef int (*varpd_plugin_nprops_f)(void *, int *);

/*
 * Obtain information about a property.
 */
typedef int (*varpd_plugin_propinfo_f)(void *, const char *,
    overlay_prop_handle_t);

/*
 * Get the value for a single property.
 */
typedef int (*varpd_plugin_getprop_f)(void *, const char *, void *, uint32_t *);

/*
 * Set the value for a single property.
 */
typedef int (*varpd_plugin_setprop_f)(void *, const char *, const void *,
    const uint32_t);

typedef struct varpd_plugin_ops {
	uint_t	vpo_callbacks;
	varpd_plugin_create_f	vpo_create;
	varpd_plugin_start_f	vpo_start;
	varpd_plugin_stop_f	vpo_stop;
	varpd_plugin_destroy_f	vpo_destroy;
	varpd_plugin_lookup_f	vpo_lookup;
	varpd_plugin_nprops_f	vpo_nprops;
	varpd_plugin_propinfo_f	vpo_propinfo;
	varpd_plugin_getprop_f	vpo_getprop;
	varpd_plugin_setprop_f	vpo_setprop;
} varpd_plugin_ops_t;

typedef varpd_plugin_register {
	uint_t		vpr_version;
	uint_t		vpr_mode;
	const char	*vpr_name;
} varpd_plugin_register_t;

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_PROVIDER_H */
