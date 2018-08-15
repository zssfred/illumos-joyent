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
 * Copyright (c) 2018 Joyent, Inc.  All rights reserved.
 */

/*
 * XXX string functions that are commonly found in assembly (ie optimized),
 * per platform, but currently are just in c. Taken from armv6 version.
 *
 * Named aarch64_subr.c since strings.c exists elsewhere.
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
