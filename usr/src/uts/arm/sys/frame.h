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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_FRAME_H
#define	_SYS_FRAME_H

#include <sys/regset.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The ARM stack frame for illumos, which includes a frame pointer based out of
 * r9, looks as follows:
 *
 *       |                          |
 *       |   Caller's parameters    |
 *       |--------------------------|
 *       | Saved Link Register (LR) |
 *       |--------------------------|
 *       | Saved Frame Pointer (R9) |
 *  R9-->|--------------------------|
 *       |    Saved Registers       |
 *       |--------------------------|
 *       |    Local Variables       |
 *  SP-->|--------------------------|
 *       |   Future Stack Growth    |
 *       |                          |
 */

struct frame {
	greg_t	fr_savfp;		/* saved frame pointer (R9) */
	greg_t	fr_savpc;		/* saved program counter (LR) */
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_FRAME_H */
