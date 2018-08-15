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

/*
 * The beginning!
 *
 * We boot into _start, where we do initial set up + call main.
 * For now our main is __fakemain since we're definitely not ready to call
 * the common main
 *
 * Things to keep in mind:
 * 	- It seems like on boot caches are disabled and TLB's are invalidated
 * 	      (not that we have virtual memory yet)
 * 	- We boot into address 0x40000000, which is the start of RAM
 * 	- We need to set the stack top. We assume we're running with 1 GB of ram
 *  	      (1024 MB), so we set the stack top to 0x80000000
 *
 */
.data
.comm	t0stack, DEFAULTSTKSZ, 32
.comm	t0, 4094, 32

ENTRY(_start)
/* Set SP to top of stack */
ldr x9, =t0stack
ldr x10, =DEFAULTSTKSZ
add sp, x9, x10
/* Enable FPU - necessary for vsnprintf */
mrs x9, cpacr_el1
orr x9, x9, 0x300000 /* bits 21:20 */
msr cpacr_el1, x9
bl _fakebop_start
SET_SIZE(_start)
