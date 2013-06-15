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

#ifndef _SYS_PCB_H
#define	_SYS_PCB_H

/*
 * ARM Process Control Block.
 *
 * TODO This is currently a stub of what we'll eventually need as its not yet
 * clear what that actually is.
 */
#include <sys/inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef	_ASM

typedef struct pcb {
	uint_t		pcb_flags;
} pcb_t;

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PCB_H */
