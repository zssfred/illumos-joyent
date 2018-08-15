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
 * Copyright 2018 (c) Joyent, Inc. All rights reserved.
 */
#include <sys/machparam.h>
#include <sys/asm_linkage.h>

/*
 * Like armv7, which at some point is probably worth more closely combining
 * we do the following:
 *
 * 1. Start in the machine speicifc locore.s
 * 2. Go into fakebop
 * 3. Goes into krtld via kobj_boot
 * 4. Exitto _locore_start (in this file)
 * 5. Go into mlsetup
 * 6. Call main!
 */

	.globl _locore_start
	.globl mlsetup

.data
.comm	t0stack, DEFAULTSTKSZ, 32
.comm	t0, 4094, 32


#if defined(__lint)

/* ARGSUSED */
void
_locore_start(struct boot_syscalls *sysp, struct bootops *bop)

#else /* __lint */

ENTRY(_locore_start)

SET_SIZE(_locore_start)

#endif /* __lint */