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
 * Copyright 2013 (c) Joyent, Inc. All rights reserved.
 */

#include <sys/asm_linkage.h>
#include <sys/machparam.h>

#if defined(__lint)

#endif

/*
 * Each of the different machines has its own locore.s to take care of getting
 * us into fakebop for the first time. After that, they all return here to a
 * generic locore to take us into mlsetup and then to main forever more.
 */

	/*
	 * External globals
	 */
	.globl	_locore_start
	.globl mlsetup
	
	.data
	.comm	t0stack, DEFAULTSTKSZ, 32
	.comm	t0, 4094, 32

#if defined(__lint)

/* ARGSUSED */
void
_locore_start(struct boot_syscalls *sysp, struct bootops *bop)
{}

#else	/* __lint */

	/*
	 * We got here from _kobj_init().  We have a few different tasks that we
	 * need to take care of before we hop into mlsetup and then main.
	 *
	 *  o Enable unaligned access
	 *  o Enable our I/D-caches
	 *  o Save the boot syscalls and bootops for later
	 *  o Set up our stack to be the real stack of t0stack.
	 */
	ENTRY(_locore_start)

	SET_SIZE(_locore_start)

#endif	/* __lint */
