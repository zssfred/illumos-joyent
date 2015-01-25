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
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 * Copyright (c) 2015 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */


#ifndef _SYS_BOOTCONF_H
#define	_SYS_BOOTCONF_H

/*
 * Boot time configuration information objects
 */

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/ccompile.h>
#include <net/if.h>			/* for IFNAMSIZ */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Masks for bsys_alloc memory allocator. These overlap with the ones for intel
 * and sun because they're used by the common kernel.
 */
#define	BO_NO_ALIGN	0x00001000
#define	BO_ALIGN_DONTCARE	-1

struct bsys_mem {
	struct memlist	physinstalled;
};

#define	BO_VERSION	1	/* bootops interface revision */

typedef struct bootops {
	uint_t	bsys_version;
	struct bsys_mem	boot_mem;
	caddr_t	(*bsys_alloc)(struct bootops *, caddr_t, size_t, int);
	void	(*bsys_free)(struct bootops *, caddr_t, size_t);
	int	(*bsys_getproplen)(struct bootops *, const char *);
	int	(*bsys_getprop)(struct bootops *, const char *, void *);
	void	(*bsys_printf)(struct bootops *, const char *, ...);
} bootops_t;

#define	BOP_GETVERSION(bop)		((bop)->bsys_version)
#define	BOP_ALLOC(bop, virthint, size, align)	\
		((bop)->bsys_alloc)(bop, virthint, size, align)
#define	BOP_FREE(bop, virt, size)	((bop)->bsys_free)(bop, virt, size)
#define	BOP_GETPROPLEN(bop, name)	((bop)->bsys_getproplen)(bop, name)
#define	BOP_GETPROP(bop, name, buf)	((bop)->bsys_getprop)(bop, name, buf)
#define	BOP_PUTSARG(bop, msg, arg)	((bop)->bsys_printf)(bop, msg, arg)

/*
 * Boot configuration information
 */

#define	BO_MAXFSNAME	16
#define	BO_MAXOBJNAME	256

struct bootobj {
	char	bo_fstype[BO_MAXFSNAME];	/* vfs type name (e.g. nfs) */
	char	bo_name[BO_MAXOBJNAME];		/* name of object */
	int	bo_flags;			/* flags, see below */
	int	bo_size;			/* number of blocks */
	struct vnode *bo_vp;			/* vnode of object */
	char	bo_devname[BO_MAXOBJNAME];
	char	bo_ifname[BO_MAXOBJNAME];
	int	bo_ppa;
};

/*
 * flags
 */
#define	BO_VALID	0x01	/* all information in object is valid */
#define	BO_BUSY		0x02	/* object is busy */

extern struct bootobj rootfs;
extern struct bootobj swapfile;

extern char *default_path;
extern int modrootloaded;
extern char kern_bootargs[];
extern char kern_bootfile[];

extern int strplumb(void);
extern char *strplumb_get_netdev_path(void);
extern void consconfig(void);
extern void release_bootstrap(void);

extern void bop_panic(const char *);
extern void boot_prop_finish(void);
extern void bop_printf(struct bootops *, const char *, ...);

extern struct bootops *bootops;
extern int netboot;
extern char *dhcack;
extern int dhcacklen;
extern char dhcifname[IFNAMSIZ];

extern char *netdev_path;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOTCONF_H */
