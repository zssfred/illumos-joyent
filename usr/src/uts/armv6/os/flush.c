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

#include <sys/types.h>

/*
 * Instruction and Data cache manipulation routines.
 *
 * The ARM architecture uses a modified Harvard Architecture which means that we
 * get the joys of fixing up this mess. Primarily this means that when we update
 * data, it gets written to do the data cache. That needs to be flushed to main
 * memory and then the instruction cache needs to be invalidated. This is
 * particularly important for things like krtld and DTrace. While the data cache
 * does write itself out over time, we cannot rely on it having written itself
 * out to the state that we care about by the time that we'd like it to. As
 * such, we need to ensure that it's been flushed out ourselves. This also means
 * that we could accidentally flush a region of the icache that's already
 * updated itself, but that's just what we have to do to keep Von Neumann's
 * spirt and great gift alive.
 *
 * The controllers for the caches have a few different options for invalidation.
 * One may:
 *
 *   o Invalidate or flush the entire cache
 *   o Invalidate or flush a cache line
 *   o Invalidate or flush a cache range
 *
 * We opt to take the third option here for the general case of making sure that
 * text has been synchronized. While the data cache allows us to both invalidate
 * and flush the cache line, we don't currently have a need to do the
 * invalidation.
 *
 * Note that all of these operations should be aligned on an 8-byte boundary.
 * The instructions actually only end up using bits [31:5] of an address. We
 * always round down the starting address and round up the ending address.
 *
 * Currently we use a single set of routines that should work on both ARMv6 and
 * ideally newer machines. Until such time as we have more optimized routines,
 * this should suffice.
 */

void
armv6_icache_inval(caddr_t start, size_t len)
{
	caddr_t end = start + len;

	start = (caddr_t)((uintptr_t)start & 0xfffffff0L);

	if (((uintptr_t)end & 0xf) != 0)
		end = (caddr_t)(((uintptr_t)start & 0xfffffff0) + 0x10);

	__asm__ __volatile__(
	    "mcrr p15, 0, %1, %0, c5\n\t"
	    : : "r" (start), "r" (end));
}

void
armv6_dcache_inval(caddr_t start, size_t len)
{
	caddr_t end = start + len;

	start = (caddr_t)((uintptr_t)start & 0xfffffff0L);

	if (((uintptr_t)end & 0xf) != 0)
		end = (caddr_t)(((uintptr_t)start & 0xfffffff0) + 0x10);

	__asm__ __volatile__(
	    "mcrr p15, 0, %1, %0, c6\n\t"
	    : : "r" (start), "r" (end));
}

void
armv6_dcache_flush(caddr_t start, size_t len)
{
	caddr_t end = start + len;

	start = (caddr_t)((uintptr_t)start & 0xfffffff0L);

	if (((uintptr_t)end & 0xf) != 0)
		end = (caddr_t)(((uintptr_t)start & 0xfffffff0) + 0x10);

	__asm__ __volatile__(
	    "mcrr p15, 0, %1, %0, c12\n\t"
	    : : "r" (start), "r" (end));
}

void
armv6_text_flush(caddr_t start, size_t len)
{
	armv6_dcache_flush(start, len);
	armv6_icache_inval(start, len);
}

void (*arm_icache_inval)(caddr_t, size_t) = armv6_icache_inval;
void (*arm_dcache_inval)(caddr_t, size_t) = armv6_dcache_inval;
void (*arm_dcache_flush)(caddr_t, size_t) = armv6_dcache_flush;
void (*arm_text_flush)(caddr_t, size_t) = armv6_text_flush;
