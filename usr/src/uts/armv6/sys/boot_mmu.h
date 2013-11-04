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

#ifndef _SYS_BOOT_MMU_H
#define	_SYS_BOOT_MMU_H

/*
 * Early MMU related routines.
 */

#include <sys/types.h>
#include <sys/atag.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void armboot_mmu_init(atag_header_t *);
extern void armboot_mmu_map(uintptr_t, uintptr_t, size_t, int);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BOOT_MMU_H */
