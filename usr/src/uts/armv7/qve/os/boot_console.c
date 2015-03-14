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
 * QEMU versatilepb boot console implementation
 *
 * QEMU's versatilepb board allows for up to three different serial consoles
 * based on the PrimeCell UART (PL011). Apparently it doesn't implement flow
 * control so all we're supposed to do is read and write to the memory address
 * to interact with it. Sigh.
 */
static volatile unsigned int *bcons_uart0addr = (void *)0x101f1000;

/*
 * For now, we only support uart0
 */
void
bcons_init(char *bstr)
{
}

void
bcons_putchar(int c)
{
	*bcons_uart0addr = c & 0x7f;
	if (c == '\n')
		bcons_putchar('\r');
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
	return (*bcons_uart0addr & 0x7f);
}

int
bcons_ischar(void)
{
	return (1);
}
