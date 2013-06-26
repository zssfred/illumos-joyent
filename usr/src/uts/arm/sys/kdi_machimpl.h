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

#ifndef _SYS_KDI_MACHIMPL_H
#define	_SYS_KDI_MACHIMPL_H

/*
 * Describe the purpose of the file here.
 */

#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/cpuvar.h>

/* XXX Should generally be present */
#if 0
#include <sys/kdi_regs.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX: This stuff is going to be rather different from x86/sparc. Rather than
 * pretend we know this interface now, we'll define a token kdi_mach struct and
 * fill this in as we have a better idea of what we need.
 */

typedef struct kdi_mach {
	void *mkdi_garbage;
} kdi_mach_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KDI_MACHIMPL_H */
