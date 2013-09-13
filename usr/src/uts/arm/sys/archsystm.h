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

#ifndef _SYS_ARCHSYSTM_H
#define	_SYS_ARCHSYSTM_H

/*
 * A selection of ISA-dependent interfaces
 */

/*
 * XXXARM: We currently don't have any use for this, but parts of the system
 * require it so as to make forward progress we instead create it for now.
 */

#if defined(_KERNEL) && !defined(_ASM)
#include <sys/types.h>
#include <sys/regset.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

extern greg_t getfp(void);
extern int getpil(void);
extern void reset(void) __NORETURN;

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ARCHSYSTM_H */
