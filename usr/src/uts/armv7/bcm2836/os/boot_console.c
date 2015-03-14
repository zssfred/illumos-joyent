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
 * bcm2836 boot console implementation
 */

#include "bcm2836_uart.h"

/*
 * There are a few different potential boot consoles that we could have on the
 * bcm2836. There is both a mini uart and a full functioning uart. Generally,
 * people will use one of them, but we want to support both. As such we have a
 * single global ops vector that we set once during bcons_init and never again.
 */
#define	BMC2836_CONSNAME_MAX	24
typedef struct bcm2836_consops {
	char bco_name[BMC2836_CONSNAME_MAX];
	void (*bco_putc)(uint8_t);
	uint8_t (*bco_getc)(void);
	int (*bco_isc)(void);
} bcm2836_consops_t;

static bcm2836_consops_t consops;

/*
 * For now, we only support the real uart.
 */
void
bcons_init(char *bstr)
{
	bcm2836_uart_init();
	consops.bco_putc = bcm2836_uart_putc;
	consops.bco_getc = bcm2836_uart_getc;
	consops.bco_isc = bcm2836_uart_isc;
}

void
bcons_putchar(int c)
{
	consops.bco_putc(c);
}

void
bcons_puts(const char *str)
{
	const char *c = str;
	while (*c != '\0')
		consops.bco_putc(*c++);
}

int
bcons_getchar(void)
{
	return (consops.bco_getc());
}

int
bcons_ischar(void)
{
	return (consops.bco_isc());
}
