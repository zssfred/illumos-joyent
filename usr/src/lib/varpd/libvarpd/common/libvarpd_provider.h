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

#include <libvarpd.h>
#include <libnvpair.h>
#include <sys/socket.h>
#include <sys/overlay_target.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	VARPD_VERSION_ONE	1
#define	VARPD_CURRENT_VERSION	VARPD_VERSION_ONE

typedef struct __varpd_provier_handle *varpd_provider_handle_t;

/*
 * Create a new instance of a plugin.
 */
typedef int (*varpd_plugin_create_f)(varpd_provider_handle_t, void **,
    overlay_plugin_dest_t);

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
 * Look up the destination specified by the overlay_targ_lookup_t and store it
 * in the overlay_target_point_t. If the value of the overlay_targ_t is NULL,
 * then that is our way of asking for a default. This function should return
 * either VARPD_LOOKUP_OK or VARPD_LOOKUP_DROP.
 *
 * Multiple threads may call this function in parallel.
 */
#define	VARPD_LOOKUP_OK		(0)
#define	VARPD_LOOKUP_DROP	(-1)
typedef int (*varpd_plugin_lookup_f)(void *, overlay_targ_lookup_t *,
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
typedef int (*varpd_plugin_nprops_f)(void *, uint_t *);

/*
 * Obtain information about a property.
 */
typedef int (*varpd_plugin_propinfo_f)(void *, const uint_t,
    varpd_prop_handle_t);

/*
 * Get the value for a single property.
 */
typedef int (*varpd_plugin_getprop_f)(void *, const char *, void *, uint32_t *);

/*
 * Set the value for a single property.
 */
typedef int (*varpd_plugin_setprop_f)(void *, const char *, const void *,
    const uint32_t);

/*
 * Save a plugin's private data into an nvlist.
 */
typedef int (*varpd_plugin_save_f)(void *, nvlist_t *);

/*
 * Restore a plugin's private data to an nvlist.
 */
typedef int (*varpd_plugin_restore_f)(nvlist_t *, varpd_provider_handle_t,
    overlay_plugin_dest_t, void **);

/*
 * Do a proxy ARP/NDP lookup.
 */
#define	VARPD_ARP_ETHERNET	0x0
typedef int (*varpd_plugin_arp_f)(void *, int, const struct sockaddr *,
    uint8_t *);

typedef struct varpd_plugin_ops {
	uint_t			vpo_callbacks;
	varpd_plugin_create_f	vpo_create;
	varpd_plugin_start_f	vpo_start;
	varpd_plugin_stop_f	vpo_stop;
	varpd_plugin_destroy_f	vpo_destroy;
	varpd_plugin_lookup_f	vpo_lookup;
	varpd_plugin_nprops_f	vpo_nprops;
	varpd_plugin_propinfo_f	vpo_propinfo;
	varpd_plugin_getprop_f	vpo_getprop;
	varpd_plugin_setprop_f	vpo_setprop;
	varpd_plugin_save_f	vpo_save;
	varpd_plugin_restore_f	vpo_restore;
	varpd_plugin_arp_f	vpo_arp;
} varpd_plugin_ops_t;

typedef struct varpd_plugin_register {
	uint_t		vpr_version;
	uint_t		vpr_mode;
	const char	*vpr_name;
	const varpd_plugin_ops_t *vpr_ops;
} varpd_plugin_register_t;

extern varpd_plugin_register_t *libvarpd_plugin_alloc(uint_t, int *);
extern void libvarpd_plugin_free(varpd_plugin_register_t *);
extern int libvarpd_plugin_register(varpd_plugin_register_t *);

/*
 * Property information callbacks
 */
extern void libvarpd_prop_set_name(varpd_prop_handle_t, const char *);
extern void libvarpd_prop_set_prot(varpd_prop_handle_t, overlay_prop_prot_t);
extern void libvarpd_prop_set_type(varpd_prop_handle_t, overlay_prop_type_t);
extern int libvarpd_prop_set_default(varpd_prop_handle_t, void *, ssize_t);
extern void libvarpd_prop_set_nodefault(varpd_prop_handle_t);
extern void libvarpd_prop_set_range_uint32(varpd_prop_handle_t, uint32_t,
    uint32_t);
extern void libvarpd_prop_set_range_str(varpd_prop_handle_t, const char *);

/*
 * Routines for proxying certain types of traffic
 */
extern int libvarpd_plugin_proxy_arp(varpd_provider_handle_t,
    overlay_targ_lookup_t *);
extern int libvarpd_plugin_proxy_ndp(varpd_provider_handle_t,
    overlay_targ_lookup_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBVARPD_PROVIDER_H */
