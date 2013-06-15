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

/*
 * Support routines for reading and parsing the various atag structures that
 * various boot loaders use.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/atag.h>
#include <sys/boot_console.h>

#define	DBG_MSG(x)	{ bcons_puts(x); bcons_puts("\n\r"); }

atag_header_t *
atag_next(atag_header_t *cur)
{
	uintptr_t addr;

	addr = (uintptr_t)cur;
	addr += cur->ah_size * 4;
	cur = (atag_header_t *)addr;
	if (cur->ah_tag == ATAG_NONE)
		return (NULL);

	return (cur);
}
