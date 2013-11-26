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

#ifndef _SYS_CPUID_IMPL_H
#define	_SYS_CPUID_IMPL_H

#include <sys/stdint.h>
#include <sys/arm_archext.h>

/*
 * Routines to read ARM cpuid co-processors
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct arm_cpuid {
	uint32_t ac_ident;
	uint32_t ac_pfr[2];
	uint32_t ac_dfr;
	uint32_t ac_mmfr[4];
	uint32_t ac_isar[6];
	uint32_t ac_fpident;
	uint32_t ac_mvfr[2];
} arm_cpuid_t;

extern uint32_t arm_cpuid_idreg();
extern uint32_t arm_cpuid_pfr0();
extern uint32_t arm_cpuid_pfr1();
extern uint32_t arm_cpuid_dfr0();
extern uint32_t arm_cpuid_mmfr0();
extern uint32_t arm_cpuid_mmfr1();
extern uint32_t arm_cpuid_mmfr2();
extern uint32_t arm_cpuid_mmfr3();
extern uint32_t arm_cpuid_isar0();
extern uint32_t arm_cpuid_isar1();
extern uint32_t arm_cpuid_isar2();
extern uint32_t arm_cpuid_isar3();
extern uint32_t arm_cpuid_isar4();
extern uint32_t arm_cpuid_isar5();

extern uint32_t arm_cpuid_vfpidreg();
extern uint32_t arm_cpuid_mvfr0();
extern uint32_t arm_cpuid_mvfr1();

#ifdef __cplusplus
}
#endif

#endif /* _SYS_CPUID_IMPL_H */
