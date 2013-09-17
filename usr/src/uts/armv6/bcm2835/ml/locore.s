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

#include <sys/asm_linkage.h>
#include <sys/machparam.h>
#include <sys/cpu_asm.h>

/*
 * Every story needs a beginning. This is ours.
 */

/*
 * We are in a primordial world here. The BMC2835 is going to come along and
 * boot us at _start. Normally we would go ahead and use a main() function, but
 * for now, we'll do that ourselves. As we've started the world, we also need to
 * set up a few things about us, for example our stack pointer. To help us out,
 * it's useful to remember the rough memory map. Remember, this is for physcial
 * addresses. There is no virtual memory here. These sizes are often manipulated
 * by the 'configuration' in the bootloader.
 *
 * +----------------+ <---- Max physical memory
 * |                |
 * |                |
 * |                |
 * +----------------+
 * |                |
 * |      I/O       |
 * |  Peripherals   |
 * |                |
 * +----------------+ <---- I/O base 0x20000000 (corresponds to 0x7E000000)
 * |                |
 * |     Main       |
 * |    Memory      |
 * |                |
 * +----------------+ <---- Top of SDRAM
 * |                |
 * |       VC       |
 * |     SDRAM      |
 * |                |
 * +----------------+ <---- Split determined by bootloader config
 * |                |
 * |      ARM       |
 * |     SDRAM      |
 * |                |
 * +----------------+ <---- Bottom of physical memory 0x00000000
 *
 * With the Raspberry Pi Model B, we have 512 MB of SDRAM. That means we have a
 * range of addresses from [0, 0x20000000). If we assume that the minimum amount
 * of DRAM is given to the GPU - 32 MB, that means we really have the following
 * range: [0, 0x1e000000).
 *
 * By default, this binary will be loaded into 0x8000. For now, that means we
 * will set our initial stack to 0x10000000.
 */

/*
 * Recall that _start is the traditional entry point for an ELF binary.
 */
	ENTRY(_start)
	ldr sp, =t0stack
	ldr r4, =DEFAULTSTKSZ
	add sp, r4
	bic sp, sp, #0xff

	/*
	 * establish bogus stacks for exceptional CPU states, our exception
	 * code should never make use of these, and we want loud and violent
	 * failure should we accidentally try.
	 */
	cps #(CPU_MODE_UND)
	mov sp, #-1
	cps #(CPU_MODE_ABT)
	mov sp, #-1
	cps #(CPU_MODE_FIQ)
	mov sp, #-1
	cps #(CPU_MODE_IRQ)
	mov sp, #-1
	cps #(CPU_MODE_SVC)

	/* Enable highvecs (moves the base of the exception vector) */
	mrc	p15, 0, r3, c1, c0, 0
	mov	r4, #1
	lsl	r4, r4, #13
	orr	r3, r3, r4
	mcr	p15, 0, r3, c1, c0, 0

	/* Disable A (disables strict alignment checks) */
	mrc	p15, 0, r3, c1, c0, 0
	bic	r3, r3, #2
	mcr	p15, 0, r3, c1, c0, 0

	/*
	 * XXX Currently we're using u-boot to allow us to make forward progress
	 * while the .data section is a bit tumultuous. It loads that, but we
	 * can say for certain that it does not correctly pass in the machid and
	 * tagstart. Since we know what it is, we manually fix it up here.
	 */
	mov r2,#0x100
	bl _fakebop_start
	SET_SIZE(_start)

	ENTRY(arm_reg_read)
	ldr r0, [r0]
	bx lr
	SET_SIZE(arm_reg_read)

	ENTRY(arm_reg_write)
	str r1, [r0]
	bx lr
	SET_SIZE(arm_reg_write)
