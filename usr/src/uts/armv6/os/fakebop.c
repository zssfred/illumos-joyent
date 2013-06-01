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

/*
 * Just like in i86pc, we too get the joys of mimicking the SPARC boot system.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/bootconf.h>
#include <sys/boot_console.h>

static bootops_t bootop;
static uint_t kbm_debug = 1;
#define	DBG_MSG(x)	{ if (kbm_debug) bcons_puts(x); bcons_puts("\n\r"); }

/*
 * Welcome to the kernel. We need to make a fake version of the boot_ops and the
 * boot_syscalls and then jump our way to _kobj_boot().
 */
void
_fakebop_start(void)
{
	bootops_t *bops = &bootop;

	/* XXX We should find the actual command line */
	bcons_init(NULL);

	/*
	 * XXX For now, we explicitly put a gating getc into place. This gives
	 * us enough time to ensure that anyone who is using the serial console
	 * is in a place where they can see output. 
	 */
	(void) bcons_getchar();
	DBG_MSG("Welcome to fakebop -- ARM edition");
	for (;;)
		;
}
