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

#ifndef _PROTOTYPE_H
#define	_PROTOTYPE_H

/*
 * ARMv6 Cross call definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The ARM general interrupt controller defines a minimum of 16 interrupt
 * priority levels. While some systems may support more, we'll stick with
 * assuming the minimum to make our lives simpler.
 */

#define	XC_HI_PIL	15		/* IPI (called SGI on ARM) */
#define	XCALL_PIL	XC_HI_PIL

#ifdef __cplusplus
}
#endif

#endif /* _PROTOTYPE_H */
