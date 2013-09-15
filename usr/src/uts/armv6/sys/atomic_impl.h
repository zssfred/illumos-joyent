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

#ifndef _SYS_ATOMIC_IMPL_H
#define	_SYS_ATOMIC_IMPL_H

/*
 * ARM atomic instruction architecture-specific deps
 *
 * The ARM architecture only first supported multi-processors in ARMv6. It
 * revised portions of that support in ARMv7. As a part of the changes in ARMv7,
 * formal instructions were given to memory barriers which traditionally were
 * just co-processor writes. ARMv6 only has the co-processor instructions. To
 * help facilitate the fact that ARMv7 only wants you to use the instructions,
 * we require that the implementations of memory barriers include this file to
 * get the correct instruction. While we only support ARMv6 at this time, this
 * is being done so we don't have the desire to go back in time and punch past
 * us in the face.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ASM

/*
 * Insert a memory barrier using the specified register as the data to move
 * there. Note that register will be clobbered. Commonly called a 'DMB'
 */
#define	ARM_DMB_INSTR(reg)	\
	mov	reg, #0;	\
	mcr	p15, 0, reg, c7, c10, 5

/*
 * Insert an instruction sync barrier. This is commonly called an 'ISB'
 */
#define	ARM_ISB_INSTR(reg)	\
	mov	reg, #0;	\
	mcr	p15, 0, reg, c7, c5, 4

/*
 * Insert a memory sync barrier. This is commonly called a 'DSB'. It is not as
 * strong as a 'DMB' and is more akin to an x86 serializing instruction.
 */
#define	ARM_DSB_INSTR(reg)	\
	mov	reg, #0;	\
	mcr	p15, 0, reg, c7, c10, 4

#endif /* _ASM */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ATOMIC_IMPL_H */
