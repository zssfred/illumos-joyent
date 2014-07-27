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
 * QEMU Versatilepb board specific functions.
 */

#include <vm/vm_dep.h>

void
armv6_bsmdep_l2cacheinfo(void)
{
	/* Per L220 Cache Controller Technical Reference Manual */
	armv6_l2cache_linesz = 32;
	/* 128 Kb l2 cache, per DUI0425F */
	armv6_l2cache_size = 0x20000;
}
