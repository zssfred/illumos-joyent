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
#include <sys/types.h>
#include <sys/time.h>

/*
 * Board Specific Module dependencies.
 */

/*
 * XXX: armv8. Seems like armv6/7 relied on board specific code to do time
 * need to look into for armv8
 */
static hrtime_t
dummy_hrtime(void)
{
	return (0);
}

/*
 * Functions for a BSM to initialize
 */
hrtime_t (*gethrtimeunscaledf)(void) = dummy_hrtime;

/*
 * General entry points
 */
hrtime_t
gethrtime_unscaled(void)
{
	return (gethrtimeunscaledf());
}
