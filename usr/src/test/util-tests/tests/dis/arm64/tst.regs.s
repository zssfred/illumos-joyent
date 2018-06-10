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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Test basic register naming
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	ADD W0, W1, W2
	ADD W3, W4, W5
	ADD W6, W7, W8
	ADD W9, W10, W11
	ADD W12, W13, W14
	ADD W15, W16, W17
	ADD W18, W19, W20
	ADD W21, W22, W23
	ADD W24, W25, W26
	ADD W27, W28, W29
	ADD W30, WSP, #1
	ADD X0, X1, X2
	ADD X3, X4, X5
	ADD X6, X7, X8
	ADD X9, X10, X11
	ADD X12, X13, X14
	ADD X15, X16, X17
	ADD X18, X19, X20
	ADD X21, X22, X23
	ADD X24, X25, X26
	ADD X27, X28, X29
	ADD X30, SP, #2

	ADD XZR, X0, X1
	ADD WZR, W1, W2
.size libdis_test, [.-libdis_test]
