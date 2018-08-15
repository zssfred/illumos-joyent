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
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

	.file	"kobj_crt.s"

/*
 * This is the exit routine that sends us off to the kernel.
 */

#include <sys/asm_linkage.h>

/*
 * exitto is designed to take us from the linker/loader into the kernel. We
 * never expect to return from here, as such we do not branch and link, but just
 * jump there directly. Our caller expects us to pass the boot syscalls as arg0
 * and the bootops as arg1.
 */

#if defined(lint)

/* ARGSUSED */
void
exitto(caddr_t entrypoint)
{}

#else	/* lint */

	ENTRY(exitto)

	mov	x2, x0 		/* Move entry point to x2 */
	ldr	x0, =romp 	/* Pass syscalls into arg1 */
	ldr	x0, [x0]
	ldr	x1, =ops 	/* Pass bootops into arg2 */
	ldr	x1, [x1]
	br	x2 		/* Jump to the entry */

	SET_SIZE(exitto)

#endif	/* lint */
