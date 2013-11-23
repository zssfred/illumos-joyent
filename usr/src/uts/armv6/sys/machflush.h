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

#ifndef _SYS_MACHFLUSH_H
#define	_SYS_MACHFLUSH_H

#include <sys/types.h>

/*
 * General cache flush and invalidation interfaces for ARM.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

void armv6_icache_inval(void);
void armv6_dcache_inval(void);
void armv6_dcache_flush(void);
void armv6_text_flush_range(caddr_t, size_t);
void armv6_text_flush(void);
void armv6_tlb_sync(void);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MACHFLUSH_H */
