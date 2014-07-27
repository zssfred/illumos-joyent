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
 * ARMv6 platform-specific sysconfig entries.
 */

#include <sys/errno.h>
#include <sys/systm.h>

/* ARGSUSED */
int
mach_sysconfig(int which)
{
	return (set_errno(EINVAL));
}

/*
 * This is called to indicate that utsname.nodename has been modified, but
 * that's entirely a no-op as far as the ARMv6 platforms care.
 */
void
nodename_set(void)
{
}
