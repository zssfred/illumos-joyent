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

#ifndef _SYS_OVERLAY_IMPL_H
#define	_SYS_OVERLAY_IMPL_H

/*
 * Overlay device support
 */

#include <sys/overlay.h>
#include <sys/overlay_common.h>
#include <sys/overlay_plugin.h>
#include <sys/overlay_target.h>
#include <sys/ksynch.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <sys/ksocket.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	OVEP_VERSION_ONE	0x1

typedef struct overlay_plugin {
	kmutex_t ovp_mutex;
	list_node_t ovp_link;			/* overlay_plugin_lock */
	uint_t ovp_active;			/* ovp_mutex */
	const char *ovp_name;			/* RO */
	const overlay_plugin_ops_t *ovp_ops;	/* RO */
	const char *const *ovp_props;		/* RO */
	uint_t ovp_nprops;			/* RO */
	uint_t ovp_id_size;			/* RO */
	overlay_plugin_flags_t ovp_flags;	/* RO */
	uint_t ovp_hdr_min;			/* RO */
	uint_t ovp_hdr_max;			/* RO */
	overlay_plugin_dest_t ovp_dest;		/* RO */
} overlay_plugin_t;

typedef struct overlay_mux {
	list_node_t		omux_lnode;
	ksocket_t		omux_ksock;	/* RO */
	overlay_plugin_t	*omux_plugin;	/* RO: associated encap */
	int			omux_domain;	/* RO: socket domain */
	int			omux_family;	/* RO: socket family */
	int			omux_protocol;	/* RO: socket protocol */
	struct sockaddr 	*omux_addr;	/* RO: socket address */
	socklen_t		omux_alen;	/* RO: sockaddr len */
	kmutex_t		omux_lock;	/* Protects everything below */
	uint_t			omux_count;	/* Active instances */
	avl_tree_t		omux_devices;	/* Tree of devices */
} overlay_mux_t;

typedef struct overlay_target {
	kmutex_t		ott_lock;
	overlay_target_mode_t	ott_mode;	/* RO */
	overlay_plugin_dest_t	ott_dest;	/* RO */
	uint64_t		ott_id;		/* RO */
	union {					/* ott_lock */
		overlay_target_point_t	ott_point;
	} ott_u;
} overlay_target_t;

typedef enum overlay_dev_flag {
	OVERLAY_F_ACTIVATED	= 0x01, /* Activate ioctl completed */
	OVERLAY_F_IN_MUX	= 0x02,	/* Currently in a mux */
	OVERLAY_F_IN_TX		= 0x04,	/* Currently doing tx */
	OVERLAY_F_IN_RX		= 0x08, /* Currently doing rx */
	OVERLAY_F_IOMASK	= 0x0c,	/* A mask for rx and tx */
	OVERLAY_F_MDDROP	= 0x10,	/* Drop traffic for metadata update */
	OVERLAY_F_VARPD		= 0x20,	/* varpd plugin exists */
	OVERLAY_F_DEGRADED	= 0x40,	/* device is degraded */
	OVERLAY_F_MASK		= 0x3f	/* mask of everything */
} overlay_dev_flag_t;

typedef struct overlay_dev {
	kmutex_t	odd_lock;
	kcondvar_t	odd_iowait;
	list_node_t	odd_link;		/* overlay_dev_lock */
	mac_handle_t	odd_mh;			/* RO */
	overlay_plugin_t *odd_plugin;		/* RO */
	datalink_id_t	odd_linkid;		/* RO */
	void		*odd_pvoid;		/* RO -- only used by plugin */
	uint_t		odd_ref;		/* protected by odd_lock */
	uint_t		odd_mtu;		/* protected by odd_lock */
	overlay_dev_flag_t odd_flags;		/* protected by odd_lock */
	overlay_mux_t	*odd_mux;		/* protected by odd_lock */
	uint64_t	odd_vid;		/* RO if active else odd_lock */
	avl_node_t	odd_muxnode;		/* managed by mux */
	overlay_target_t *odd_target;		/* XXX Write once? */
} overlay_dev_t;

#define	OVERLAY_CTL	"overlay"

extern dev_info_t *overlay_dip;

extern void overlay_plugin_init(void);
extern overlay_plugin_t *overlay_plugin_lookup(const char *);
extern void overlay_plugin_rele(overlay_plugin_t *);
extern void overlay_plugin_fini(void);
typedef int (*overlay_plugin_walk_f)(overlay_plugin_t *, void *);
extern void overlay_plugin_walk(overlay_plugin_walk_f, void *);

extern void overlay_io_start(overlay_dev_t *, overlay_dev_flag_t);
extern void overlay_io_done(overlay_dev_t *, overlay_dev_flag_t);

extern void overlay_mux_init(void);
extern void overlay_mux_fini(void);

extern overlay_mux_t *overlay_mux_open(overlay_plugin_t *, int, int, int,
    struct sockaddr *, socklen_t, int *);
extern void overlay_mux_close(overlay_mux_t *);
extern void overlay_mux_add_dev(overlay_mux_t *, overlay_dev_t *);
extern void overlay_mux_remove_dev(overlay_mux_t *, overlay_dev_t *);
extern int overlay_mux_tx(overlay_mux_t *, struct msghdr *, mblk_t *);

extern void overlay_prop_init(overlay_prop_handle_t);

extern void overlay_target_init(void);
extern int overlay_target_open(dev_t *, int, int, cred_t *);
extern int overlay_target_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern int overlay_target_close(dev_t, int, int, cred_t *);
extern void overlay_target_free(overlay_dev_t *);
extern int overlay_target_lookup(overlay_dev_t *, mblk_t *, struct sockaddr *,
    socklen_t *);
extern void overlay_target_fini(void);

extern void overlay_fm_init(void);
extern void overlay_fm_fini(void);
extern void overlay_fm_degrade(overlay_dev_t *);
extern void overlay_fm_restore(overlay_dev_t *);

extern overlay_dev_t *overlay_hold_by_dlid(datalink_id_t);
extern void overlay_hold_rele(overlay_dev_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_OVERLAY_IMPL_H */
