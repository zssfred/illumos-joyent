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

/*
 * Broadcom 2835 board specific functions.
 */

#include <vm/vm_dep.h>

void
armv6_bsmdep_l2cacheinfo(void)
{
	/*
	 * Per the BCM 2835 ARM peripherals manual, the L2 cache on the BCM
	 * 2835 is actually used by the GPU, and from the CPU point of view,
	 * we don't have one.
	 *
	 * This can be toggled on the rPi, but it appears that that toggling
	 * can't be probed for.
	 *
	 * At present, we set these variables as if we owned the l2,
	 * regardless of whether we in fact do.  This might be a terrible
	 * idea.
	 *
	 * XXX: It might be reasonable to demand that we (the CPU) have the l2
	 * cache, although since it is off-chip this may actually hinder
	 * performance.
	 */

	armv6_l2cache_linesz = 32;
	/* 128K per the BCM2835 manual, though we by default see none of it */
	armv6_l2cache_size = 0x20000;
}
