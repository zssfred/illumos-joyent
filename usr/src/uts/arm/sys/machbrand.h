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

#ifndef _SYS_MACHBRAND_H
#define	_SYS_MACHBRAND_H

/*
 * ARM-specific brand pieces
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	_ASM

struct brand_mach_ops {
	void	(*b_syscall)(void);
};

#endif	/* _ASM	*/

#define	BRAND_CB_SYSCALL	0

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MACHBRAND_H */
