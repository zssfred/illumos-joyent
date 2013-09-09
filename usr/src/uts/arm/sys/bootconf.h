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
 */


#ifndef _SYS_BOOTCONF_H
#define	_SYS_BOOTCONF_H

/*
 * Boot time configuration information objects
 */

#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/ccompile.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Masks for bsys_alloc memory allocator. These overlap with the ones for intel
 * and sun because they're used by the common kernel.
 */
#define	BO_NO_ALIGN	0x00001000
#define	BO_ALIGN_DONTCARE	-1

#define	BO_VERSION	1	/* bootops interface revision */

typedef struct bootops {
	uint_t	bsys_version;
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

extern char *default_path;
extern int modrootloaded;
extern char kern_bootargs[];
extern char kern_bootfile[];

extern int strplumb(void);
extern void consconfig(void);
extern void release_bootstrap(void);

extern void bop_panic(const char *);
extern void boot_prop_finish(void);
extern void bop_printf(struct bootops *, const char *, ...);

extern struct bootops *bootops;
#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOTCONF_H */
