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
 * Miscelaneous string functions which are found in various assembly files in
 * other platfors which some day could be optimized on ARM, but seriously.
 */

#include <sys/types.h>

size_t
strlen(const char *s)
{
	const char *e;

	/* TODO Panic on debug if below postbootkernelbase */
	for (e = s; *e != '\0'; e++)
		;
	return (e - s);
}
