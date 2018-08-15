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

/*
 * Qemu's virt board (similar to VersatilePB) seems like it doesn't actually
 * require set up or interfacing with, just writing/reading to/from the address.
 *
 * I also think it only supports uart0, not sure, but that's all we support :)
 */

volatile unsigned int * const uart_addr = (unsigned int  *)0x09000000;

void
bcons_init(char *bstr)
{
}

void
bcons_putchar(int c)
{
	*uart_addr = (unsigned int)(c & 0x7f);
	if (c == '\n')
		*uart_addr = (unsigned int)('\r' & 0x7f);
	else if (c == '\r')
		*uart_addr = (unsigned int)('\n' & 0x7f);
}

void
bcons_puts(const char *str)
{
	const char *c = str;
	while (*c != '\0')
		bcons_putchar(*c++);
}

int
bcons_getchar(void)
{
	return (*uart_addr & 0x7f);
}

int
bcons_ischar(void)
{
	return (1);
}
