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
 * Copyright 2014 (c) Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_ARMV7_BSMF_H
#define	_SYS_ARMV7_BSMF_H

/*
 * This describes interfaces that unix can expect each of the board specific
 * modules to have implemented.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The platform should fill in the values for armv7_l2cache_linesz and
 * armv7_l2cache_size.
 */
extern void armv7_bsmdep_l2cacheinfo(void);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ARMV7_BSMF_H */
