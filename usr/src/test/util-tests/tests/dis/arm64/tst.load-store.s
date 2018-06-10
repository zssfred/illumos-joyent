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
 * Test Data - Immediate group dissassembly
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/* Load Register - literal */
	LDR WZR, PC_TARGET
	LDR X9, PC_TARGET
	LDRSW XZR, PC_TARGET
	LDRSW X19, PC_TARGET
	PRFM #0xf, PC_TARGET

	/* Pre-Index */
	STP W9, W10, [X9, #16]!
	LDP W1, W2, [X3, #12]!
	LDPSW X10, XZR, [SP, #8]!

	/* Post-Index */
	STP X9, X13, [SP], #16
	LDP X15, X10, [X19], #-8
	LDPSW X10, XZR, [SP], #12

	/* Signed offset */
	STP X9, X13, [SP]
	LDP W8, W4, [SP, #28]
	LDPSW X1, XZR, [SP, #-16]

	/* Load/store no-allocate pair (offset) */
	LDNP W0, W4, [X9, #-4]
	LDNP X10, X19, [SP]
	STNP W9, W16, [SP, #24]
	STNP X10, X1, [X19, #8]

	PC_TARGET: ADD X0, X0, X0

.size libdis_test, [.-libdis_test]
