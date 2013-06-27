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

#ifndef _SYS_MACHCPUVAR_H
#define	_SYS_MACHCPUVAR_H

/*
 * XXX: ARM Machine specific CPU bits
 *
 * Like many files, we haven't even gotten to the parts of the ARM machpcb that
 * we care about. Until we do, this is basically a stub.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct machcpu {
	void *garbage;
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MACHCPUVAR_H */
