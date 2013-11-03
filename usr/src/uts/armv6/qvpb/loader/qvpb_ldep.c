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

#include <sys/elf.h>
#include <sys/atag.h>

/*
 * The loader on qemu always just uses the default PL011. No initialization
 * needed.
 */

static volatile unsigned int *flb_uart = (void *)0x101f1000;

void
fakeload_backend_init(void)
{
}

void
fakeload_backend_putc(int c)
{
	*flb_uart = c & 0x7f;
	if (c == '\n')
		fakeload_backend_putc('\r');
}

/*
 * Add a map for the uart.
 */
void
fakeload_backend_addmaps(atag_header_t *chain)
{
	atag_illumos_mapping_t aim;

	aim.aim_header.ah_size = ATAG_ILLUMOS_MAPPING_SIZE;
	aim.aim_header.ah_tag = ATAG_ILLUMOS_MAPPING;
	aim.aim_paddr = 0x101f1000;
	aim.aim_vaddr = 0x101f1000;
	aim.aim_vlen = 0x1000;
	aim.aim_plen = 0x1000;
	aim.aim_mapflags = PF_R | PF_W | PF_NORELOC | PF_DEVICE;
	atag_append(chain, &aim.aim_header);
}
