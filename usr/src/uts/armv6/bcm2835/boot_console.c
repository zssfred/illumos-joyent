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
 * bmc2835 boot console implementation
 */

#include "miniuart.h"

/*
 * There are a few different potential boot consoles that we could have on the
 * bmc2835. There is both a mini uart and a full functioning uart. Generally,
 * people will use the mini uart, but we want to support both. As such we have a
 * single global ops vector that we set once during bcons_init and never again.
 */
#define	BMC2835_CONSNAME_MAX	24
typedef struct bmc2835_consops {
	char bco_name[BMC2835_CONSNAME_MAX];
	void (*bco_putc)(uint8_t);
	uint8_t (*bco_getc)(void);
} bmc2835_consops_t;

static bmc2835_consops_t consops;

/*
 * For now, we only support the mini uart.
 */
void
bcons_init(char *bstr)
{
	bmc2835_miniuart_init();
	consops.bco_putc = bmc2835_miniuart_putc;
	consops.bco_getc = bmc2835_miniuart_getc;
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
