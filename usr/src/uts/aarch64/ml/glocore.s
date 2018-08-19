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
 * Copyright 2018 (c) Joyent, Inc. All rights reserved.
 */
#include <sys/machparam.h>
#include <sys/asm_linkage.h>

#include "assym.h"

/*
 * Like armv7, which at some point is probably worth more closely combining
 * we do the following:
 *
 * 1. Start in the machine speicifc locore.s
 * 2. Go into fakebop
 * 3. Goes into krtld via kobj_boot
 * 4. Exitto _locore_start (in this file)
 * 5. Go into mlsetup
 * 6. Call main!
 */

	.globl _locore_start
	.globl mlsetup
	.globl sysp
	.globl bootops
	.globl bootopsp
	.globl t0

.data
.comm	t0stack, DEFAULTSTKSZ, 32
.comm	t0, 4094, 32


#if defined(__lint)

/* ARGSUSED */
void
_locore_start(struct boot_syscalls *sysp, struct bootops *bop)

#else /* __lint */

/*
 * When we reach _locore_start we have been through:
 *	1. A machine specific locore.s (_start)
 *	2. _fakebop_start, which sets up the bootops
 *	3. _kobj_init, which calls exitto to take us here!
 *
 * Here, we need to do the following:
 *	1. XXX:
 *		- Reset the stack for main + ensure its alignment
 *		- Save boot syscalls/bootops for later?
 *		- Enable unaligned access? -- i think enabled by default. otherwise set SCTLR_EL1.A (bit 1) to 0
 *		- Enable I/D caches
 *		- save t0 as curthread
 * 	2. Call mlsetup(struct regs) initializing various thread/CPU state data
 *	3. Enter main!
 *		3.5. Main should never return, panic if we do :(
 *
 * XXX: things well probably ahve to do later
 *	set up thread pointer
 *	handle frame pointer?
 */

	ENTRY(_locore_start)

	/*
	 * Set up the stack to hold struct regs
	 * Many of these operations cannot be done directly on sp, so
	 * load the 16 byte aligned value into x9 and move that to sp
	 */
	ldr x9, =t0stack
	ldr x10, =DEFAULTSTKSZ
	ldr x11, =REGSIZE
	sub x10, x10, x11
	add x9, x9, x10 /* x9 is now a pointer to struct regs */
	mov x10, #0xffff
	bic x11, x9, x10
	mov sp, x11 /* and sp is now an aligned version of it */

	/* Optionally here, we can save our args to the struct regs */
	//XXX do this once we have assym.h working
	// str x0, [x9, #REGOFF_R0]
	// str x1, [x9, #REGOFF_R1]

	/* Setup t0 as our curthread pointer */
	ldr x20, =t0
	msr tpidr_el0, x20

	/*
	 * Make sure our caches + unaligned access is enabled (for instructions
	 * that support it). Our caches definitely don't start enabled,
	 * not sure about unaligned access
	 *
	 * sctlr_el1[1] = sctlr_el1.A:
	 *	When 1 enables alignment fault checking
	 * sctlr_el1[2] = sctlr_el1.C:
	 *	When 0 prevents normal memory accesses from being cached
	 * sctlr_el1[12] = sctlr_el1.C:
	 *	When 0 prevents instruction memory accesses from being cached
	 */
	mrs x11, sctlr_el1
	mov x10, #0x1
	bics x11, x11, x10, lsl #1 /* Disable alignment */
	orr x11, x11, x10, lsl #2 /* enable d-cache */
	orr x11, x11, x10, lsl #12 /* enable i-cache */
	msr sctlr_el1, x11

	/*
	 * Call mlsetup with struct regs (currently in x9)
	 * Also zero out the frame + link register to avoid going back up the
	 * stack (which shouldn't happen)
	 */
	mov x0, x9
	mov x29, #0 /* x29 = frame pointer */
	mov x30, #0 /* x30 = link register */
	bl mlsetup
	bl main

	/* NOTREACHED */
	ldr	x0,=__return_from_main
	ldr	x0, [x0]
	bl 	panic
	SET_SIZE(_locore_start)
__return_from_main:
	.string "main() returned"
#endif /* __lint */
