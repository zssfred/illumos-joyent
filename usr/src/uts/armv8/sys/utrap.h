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

#ifndef _UTRAP_H
#define	_UTRAP_H

/*
 * This contains definitions for user level traps which are not currently
 * supported on ARM. There is no support for install_utrap().
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	_ASM

#define	UTH_NOCHANGE ((utrap_handler_t)(-1))
#define	UTRAP_UTH_NOCHANGE	UTH_NOCHANGE

typedef int utrap_entry_t;
typedef void *utrap_handler_t;

#endif	/* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _UTRAP_H */
