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

#ifndef _SYS_DDI_ISA_H
#define	_SYS_DDI_ISA_H

/*
 * ARM DDI Implementaion Functions
 */
#include <sys/isa_defs.h>
#include <sys/dditypes.h>
#include <sys/ndifm.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX: There isn't a ton of symmetry between the intel and sparc ddi impl
 * portions. Rather than try and guess which one to use, we're going to leave
 * this empty until we have functions that we know we need implementations for.
 */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_DDI_ISA_H */
