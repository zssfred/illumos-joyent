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
 * Copying related functions which are commonly found in assembly, but let's
 * write highly optimized asm when we have an OS that can boot.
 */

#include <sys/types.h>

/*
 * bcopy handles overlap. So we have four different overlap cases.
 *
 * 1) No overlap, copy forwards or backwards
 * 2) 100% overlap, src == dest, copy forwards or backwards or return
 * 3) partial overlap, src < dest, copy backwards
 * 4) partial overlap, dest < src, copy forwards
 *
 */
void
bcopy(const void *s, void *d, size_t n)
{
	const char *src = s;
	char *dest = d;
	int i;

	if (n == 0 || s == d)
		return;

	if (dest < src && dest + n < src) {
		/* dest overlaps with the start of src, copy forward */
		for (; n > 0; n--, src++, dest++)
			*dest = *src;
	} else {
		/* src overlaps with start of dest or no overlap, copy rev */
		src += n - 1;
		dest += n - 1;
		for (; n > 0; n--, src--, dest--)
			*dest = *src;
	}
}
