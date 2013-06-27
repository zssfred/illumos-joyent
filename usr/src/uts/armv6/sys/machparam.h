/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_MACHPARAM_H
#define	_SYS_MACHPARAM_H

#if !defined(_ASM)
#include <sys/types.h>
#endif

/*
 * Machine dependent paramenters and limits
 */

/*
 * XXXARM This is a stub and will need to evolve as we get further along. For
 * now this just has a few things that we know to be the case.
 */
#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX Okay, let's be honest. We haven't even tested more than one CPU at all
 * here, but armv6 can support two CPUs at least. ARMv7 likely can support more.
 * At this point, it's not really clear how the different archs will work in the
 * kernel. Until we figure that out, we'll roll this way.
 */
#define	NCPU		2
#define	NCPU_LOG2	1

/*
 * Define the FPU symbol if we could run on a machine with an external
 * FPU (i.e. not integrated with the normal machine state like the vax).
 *
 * The fpu is defined in the architecture manual, and the kernel hides
 * its absence if it is not present, that's pretty integrated, no?
 */

/* supported page sizes */
#define	MMU_PAGE_SIZES	4	/* 4k, 64k, 1M, 16M */

/*
 * MMU_PAGES* describes the physical page size used by the mapping hardware.
 * PAGES* describes the logical page size used by the system.
 */

#define	MMU_PAGESIZE	0x1000		/* 4096 bytes */
#define	MMU_PAGESHIFT	12		/* log2(MMU_PAGESIZE) */

#define	MMU_PAGEOFFSET	(MMU_PAGESIZE-1) /* Mask of address bits in page */
#define	MMU_PAGEMASK	(~MMU_PAGEOFFSET)

#define	PAGESIZE	0x1000		/* All of the above, for logical */
#define	PAGESHIFT	12
#define	PAGEOFFSET	(PAGESIZE - 1)
#define	PAGEMASK	(~PAGEOFFSET)

/*
 * DATA_ALIGN is used to define the alignment of the Unix data segment.
 */
#define	DATA_ALIGN	PAGESIZE

/*
 * DEFAULT KERNEL THREAD stack size (in pages).
 */
#define	DEFAULTSTKSZ_NPGS	3
#define	DEFAULTSTKSZ	(DEFAULTSTKSZ_NPGS * PAGESIZE)

/*
 * KERNELBASE is the virtual address at which the kernel segments start in
 * all contexts.
 *
 * TODO Fill in more about base addresses in VM as we need them.
 */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MACHPARAM_H */
