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

#ifndef _SYS_CPU_H
#define	_SYS_CPU_H

/*
 * This header is generally Obsolete across different architectures. We should
 * include the bare minimum for compatability and nothing more. If you're adding
 * something here, think twice about that.
 */

/*
 * Include generic bustype cookies.
 */
#include <sys/bustypes.h>

extern void arm_smt_pause(void);
#define	SMT_PAUSE()	arm_smt_pause()

#endif /* _SYS_CPU_H */
