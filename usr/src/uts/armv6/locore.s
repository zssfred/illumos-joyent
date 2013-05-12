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
	mov sp,#0x8000
	bl __fakemain
	SET_SIZE(_start)
