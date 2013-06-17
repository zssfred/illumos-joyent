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

#ifndef _SYS_FLUSH_H
#define	_SYS_FLUSH_H

#include <sys/types.h>

/*
 * General cache flush and invalidation interfaces for ARM.
 *
 * These routines will always point to a flush routine for the specific ARM
 * processor that we're on. the arm_text_flush() routine takes care of making
 * sure that the d-cache is synchronized to memory and that the i-cache is
 * invalidated such that subsequant implementations will be able to do their
 * work.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern void (*arm_icache_inval)(caddr_t, size_t);
extern void (*arm_dcache_inval)(caddr_t, size_t);
extern void (*arm_dcache_flush)(caddr_t, size_t);
extern void (*arm_text_flush)(caddr_t, size_t);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FLUSH_H */
