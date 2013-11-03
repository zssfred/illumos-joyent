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
 * Copyright 2013 (c) Joyent, Inc. All rights reserved.
 */

/*
 * Every story needs a beginning, this is the loader's.
 */

#include <sys/asm_linkage.h>

	ENTRY(_start)
	mov	sp, #0x8000
	/*
	 * XXX manually fix up the tag start
	 */
	mov	r2, #0x100
	bl	fakeload_init
	SET_SIZE(_start)

#if defined(__lint)

/* ARGSUSED */
void
fakeload_unaligned_enable(void)
{}

#else 	/* __lint */

	/*
	 * Fix up alignment by turning off A and by turning on U.
	 */
	ENTRY(fakeload_unaligned_enable)
	mrc	p15, 0, r0, c1, c0, 0
	orr	r0, #0x400000
	mcr	p15, 0, r0, c1, c0, 0
	bx	lr
	SET_SIZE(fakeload_unaligned_enable);

#endif	/* __lint */

#if defined(__lint)

fakeload_pt_setup(uintptr_t ptroot)
{}

#else /* __lint */

	/*
	 * We need to set up the world for the first time. We'll do the
	 * following in order:
	 *
	 * o Set the TTBCR to always use TTBR0
	 * o Set domain 0 to manager mode
	 * o Program the Page table root
	 */
	ENTRY(fakeload_pt_setup)
	mov	r1, #0
	mcr	p15, 0, r1, c2, c0, 2
	mov	r1, #3
	mcr	p15, 0, r1, c3, c0, 0
	orr	r0, r0, #0x1b
	mcr	p15, 0, r0, c2, c0, 0
	bx	lr
	SET_SIZE(fakeload_pt_setup)

#endif /* __lint */

#if defined(__lint)

/* ARGSUSED */
void
fakeload_mmu_enable(void)
{}

#else	/* __lint */

	/*
	 * We first make sure that the ARMv6 pages are enabled (bit 23) and then
	 * enable the MMU (bit 0).
	 */
	ENTRY(fakeload_mmu_enable)
	mrc	p15, 0, r0, c1, c0, 0
	orr	r0, #0x800000
	mcr	p15, 0, r0, c1, c0, 0
	mrc	p15, 0, r0, c1, c0, 0
	orr	r0, #0x1
	mcr	p15, 0, r0, c1, c0, 0
	bx	lr
	SET_SIZE(fakeload_mmu_enable)
#endif	/* __lint */


	ENTRY(fakeload_exec)
	mov	r4, r0
	mov	r2, #0x100
	blx	r4
	/* We should never execute this. If we do we'll go back to a panic */
	bx	lr
	SET_SIZE(fakeload_exec)
