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
 * The majority of the logic is implemented in uts/aarch64/ml/cache.s. See its
 * explanation for why this is necessary on ARM.
 */
void
arm_text_flush(caddr_t start, size_t len)
{
	// aarch64_text_flush_range(start, len);
	///XXX we should implement this. however the assembly arm gave us
	//hangs, and the i-cache is disabled when this is called during
	// krtld anyways...
}