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

/*
 * XXX
 * This is almost certainly an incomplete list of flags. Some of them are
 * expected to exist, eg. NORMAL_STEP, by functions like issig_forreal.
 *
 * Currently this is the minimum combination of intel and sparc flags that are
 * used by common code. There may be additions and subtractions to the final set
 * used here.
 */
#define	PRSTOP_CALLED	0x01	/* prstop() has been called for this lwp */
#define	INSTR_VALID	0x02	/* value in pcb_instr is valid (/proc) */
#define	NORMAL_STEP	0x04	/* normal debugger requested single-step */
#define	WATCH_STEP	0x08	/* single-stepping in watchpoint emulation */
#define	CPC_OVERFLOW	0x10	/* performance counters overflowed */
#define	ASYNC_HWERR	0x20	/* asynchronous h/w error (e.g. parity error) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PCB_H */
