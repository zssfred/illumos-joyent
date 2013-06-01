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
 * Copyright 2013 (c) Joyent, Inc.  All rights reserved.
 */

/*
 * A simple uart driver for the RPi.
 */
#include <sys/types.h>

extern uint32_t arm_reg_read(uint32_t);
extern void arm_reg_write(uint32_t, uint32_t);

/*
 * The primary serial console that we end up using is not in fact a normal UART,
 * but is instead actually a mini-uart that shares interrupts and registers with
 * the SPI masters as well. While the RPi also supports another more traditional
 * UART, that isn't what we are actually hooking up to generally with the
 * adafruit cable. We already wasted our time having to figure that out. -_-
 */

#define	AUX_BASE	0x20215000
#define	AUX_ENABLES	0x4
#define	AUX_MU_IO_REG	0x40
#define	AUX_MU_IER_REG	0x44
#define	AUX_MU_IIR_REG	0x48
#define	AUX_MU_LCR_REG	0x4C
#define	AUX_MU_MCR_REG	0x50
#define	AUX_MU_LSR_REG	0x54
#define	AUX_MU_CNTL_REG	0x60
#define	AUX_MU_BAUD	0x68

#define	AUX_MU_RX_READY	0x01
#define	AUX_MU_TX_READY	0x20

/*
 * For the mini UART, all we care about are pins 14 and 15 for the UART. Specifically,
 * alt5 for GPIO14 is TXD1 and GPIO15 is RXD1. Those are controlled by FSEL1.
 */
#define	GPIO_BASE	0x20200000
#define	GPIO_FSEL1	0x4
#define	GPIO_PUD	0x94
#define	GPIO_PUDCLK0	0x98

#define	GPIO_SEL_ALT5	0x2
#define	GPIO_UART_MASK	0xfffc0fff
#define	GPIO_UART_TX_SHIFT	12
#define	GPIO_UART_RX_SHIFT	15

#define	GPIO_PUD_DISABLE	0x0
#define	GPIO_PUDCLK_UART	0x0000c000

/*
static uint32_t
arm_reg_read(uint32_t reg)
{
	uint32_t *val;

	val = (uint32_t *)reg;
	return (*val);
}

static void
arm_reg_write(uint32_t reg, uint32_t val)
{
	uint32_t *vptr = (uint32_t *)reg;
	*vptr = val;
	__asm__ volatile ("" : : : "memory");
}
*/

/*
 * A simple nop
 */
static void
arm_nop(void)
{
	__asm__ volatile ("mov r0, r0\n" : : :);
}

static void
uart_init(void)
{
    unsigned int ra;
	uint32_t v;
	int i;

	/* Enable the mini UAT */
	arm_reg_write(AUX_BASE + AUX_ENABLES, 0x1);

	/* Disable interrupts */
	arm_reg_write(AUX_BASE + AUX_MU_IER_REG, 0x0);

	/* Disable the RX and TX */
	arm_reg_write(AUX_BASE + AUX_MU_CNTL_REG, 0x0);

	/*
	 * Enable 8-bit word lenght. External sources tell us the PRM is buggy
	 * here and that even though bit 1 is reserved, we need to actually set
	 * it to get 8-bit words.
	 */
	arm_reg_write(AUX_BASE + AUX_MU_LCR_REG, 0x3);

	/* Set RTS high */
	arm_reg_write(AUX_BASE + AUX_MU_MCR_REG, 0x0);

	/* Disable interrupts */
	arm_reg_write(AUX_BASE + AUX_MU_IER_REG, 0x0);

	/* Set baud rate */
	arm_reg_write(AUX_BASE + AUX_MU_IIR_REG, 0xc6);
	arm_reg_write(AUX_BASE + AUX_MU_BAUD, 0x10e);

	v = arm_reg_read(GPIO_BASE + GPIO_FSEL1);
	v &= GPIO_UART_MASK;
	v |= GPIO_SEL_ALT5 << GPIO_UART_RX_SHIFT;
	v |= GPIO_SEL_ALT5 << GPIO_UART_TX_SHIFT;
	arm_reg_write(GPIO_BASE + GPIO_FSEL1, v);

	arm_reg_write(GPIO_BASE + GPIO_PUD, GPIO_PUD_DISABLE);
	for (i = 0; i < 150; i++)
		arm_nop();
	arm_reg_write(GPIO_BASE + GPIO_PUDCLK0, GPIO_PUDCLK_UART);
	for (i = 0; i < 150; i++)
		arm_nop();
	arm_reg_write(GPIO_BASE + GPIO_PUDCLK0, 0);

	/* Finally, go back and enable RX and TX */
	arm_reg_write(AUX_BASE + AUX_MU_CNTL_REG, 0x3);
  
}

static void
uart_putc(uint8_t c)
{
	uint32_t v;
	for (;;) {
		if (arm_reg_read(AUX_BASE + AUX_MU_LSR_REG) & AUX_MU_TX_READY)
			break;
	}
	arm_reg_write(AUX_BASE + AUX_MU_IO_REG, c & 0x7f);
}

static uint8_t
uart_getc(void)
{
	for (;;) {
		if (arm_reg_read(AUX_BASE + AUX_MU_LSR_REG) & AUX_MU_RX_READY)
			break;
	}
	return (arm_reg_read(AUX_BASE + AUX_MU_IO_REG) & 0x7f);
}

void
uart_main(void)
{
	const char *hello = "Hello, World\r\n";
	unsigned int i;
	uart_init();
	for (;;) {
		uart_putc(uart_getc());
		for (i = 0; i < 14; i++) {
			uart_putc(hello[i]);
		}
	}
}
