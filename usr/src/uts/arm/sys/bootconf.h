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


#ifndef _SYS_BOOTCONF_H
#define	_SYS_BOOTCONF_H

/*
 * Boot time configuration information objects
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	BO_VERSION	1	/* bootops interface revision */

typedef struct bootops {
	/*
	 * the ubiquitous version number
	 */
	uint_t	bsys_version;

} bootops_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOTCONF_H */
