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
#include <sys/machflush.h>

/*
 * Instruction and Data cache manipulation routines.
 *
 * The majority of the logic is implemented in uts/armv7/ml/cache.s. See its
 * explanation for why this is necessary on ARM.
 */
void
arm_text_flush(caddr_t start, size_t len)
{
	uintptr_t end = (uintptr_t)start + len;
	/*
	 * Make sure that these are 32-bit aligned and fix up appropriately for
	 * other functions.
	 */
	if (((uintptr_t)start & 0xf) != 0) {
		start = (caddr_t)((uintptr_t)start & ~(0xfUL));
	}

	if ((end & 0xf) != 0) {
		len &= ~(0xfUL);
		len += 0x10;
	}

	armv7_text_flush_range(start, len);
}
