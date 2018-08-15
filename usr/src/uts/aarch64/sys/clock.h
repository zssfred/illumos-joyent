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
 * Copyright 2013 (c) Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_CLOCK_H
#define	_SYS_CLOCK_H

/*
 * Various bits related to system time.
 *
 * XXX This header is incomplete and more details for it will need to be filled
 * in.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * This is used for get_hrestime. We use this value to adjust the time that we
 * read.
 */
#define	ADJ_SHIFT 4

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CLOCK_H */
