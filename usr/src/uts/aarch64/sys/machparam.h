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
 * Machine dependent paramenters and limits, ARM edition
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ASM
#define	ADDRESS_C(c)    c ## ul
#else   /* _ASM */
#define	ADDRESS_C(c)    (c)
#endif  /* _ASM */

/*
 * XXX Okay, let's be honest. We haven't even tested more than one CPU at all
 * here, but ARMv7 can support at least 8.
 * At this point, it's not really clear how the different archs will work in the
 * kernel. Until we figure that out, we'll roll this way.
 */
#define	NCPU		8
#define	NCPU_LOG2	3

/* NCPU_P2 is NCPU rounded to a power of 2 */
#define	NCPU_P2	(1 << NCPU_LOG2)

/*
 * Define the FPU symbol if we could run on a machine with an external
 * FPU (i.e. not integrated with the normal machine state like the vax).
 *
 * The fpu is defined in the architecture manual, and the kernel hides
 * its absence if it is not present, that's pretty integrated, no?
 */

/* supported page sizes */
#define	MMU_PAGE_SIZES	3	/* 4k, 16k 64k*/

/*
 * MMU_PAGES* describes the physical page size used by the mapping hardware.
 * PAGES* describes the logical page size used by the system.
 */

#define	MMU_PAGESIZE	0x1000		/* 4096 bytes */
#define	MMU_PAGESHIFT	12		/* log2(MMU_PAGESIZE) */
#define	MMU_PAGEOFFSET	(MMU_PAGESIZE-1) /* Mask of address bits in page */
#define	MMU_PAGEMASK	(~MMU_PAGEOFFSET)

#define	MMU_PAGESHIFT16K	14
#define	MMU_PAGESIZE16K		(1 << MMU_PAGESHIFT16K)
#define	MMU_PAGEOFFSET16K	(MMU_PAGESIZE16K - 1)
#define	MMU_PAGEMASK16K		(~MMU_PAGEOFFSET16K)

#define	MMU_PAGESHIFT64K	16
#define	MMU_PAGESIZE64K		(1 << MMU_PAGESHIFT64K)
#define	MMU_PAGEOFFSET64K	(MMU_PAGESIZE64K - 1)
#define	MMU_PAGEMASK64K		(~MMU_PAGEOFFSET64K)

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
 * XXXAARCH64: amd64 uses 5 so use 5.
 */
#define	DEFAULTSTKSZ_NPGS	5
#define	DEFAULTSTKSZ	(DEFAULTSTKSZ_NPGS * PAGESIZE)


/* XXXAARCH64: missing many defiens from this file, we'll fill in as needed. */

/* This is where amd64 defines theirs... */
#define	KERNELBASE	ADDRESS_C(0xfffffd8000000000)

/* XXX some archs leave a redzone. Not sure about this one*/
#define	USERLIMIT	KERNELBASE
#define	USERLIMIT32	USERLIMIT

/* XXX: really not sure about this one but amd64, i386 and armv7 all agree on this one */
#define	ARGSBASE	ADDRESS_C(0xffc00000)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MACHPARAM_H */
