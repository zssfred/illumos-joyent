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
	/* ADR{P} */
	ADR XZR, branch_target
	ADRP X0, libdis_test

	/* ADD/SUB - Immediate */
	ADD W0, WSP, #4
	ADD WSP, W19, #1, LSL #12
	ADDS X10, X1, #255
	ADDS X10, SP, #255
	SUB SP, X1, #16, LSL #12
	SUBS X0, SP, #8

	/*TODO: Logical - immediate */

	/* Move wide - immediate */
	MOVN W4, #65000, LSL #16
	MOVN X15, #255, LSL #48
	MOVZ W4, #1
	MOVZ X13, #2, LSL #32
	MOVK WZR, #16
	MOVK X0, #4, LSL #16

	/* Bitfield - immediate */
	SBFM W4, W9, #0, #0
	SBFM X3, X10, #1, #9
	BFM W4, W9, #0, #31
	BFM X10, XZR, #2, #57
	UBFM W1, W9, #23, #3
	UBFM XZR, X0, #0, #6

	/* Extract */
	EXTR W0, W1, WZR, #31
	EXTR W0, WZR, W1, #4
	EXTR WZR, W5, W30, #1
	EXTR X11, X1, XZR, #60
	EXTR X18, XZR, X19, #43
	EXTR XZR, X25, X30, #3

	branch_target: ADD X0, X0, X0

.size libdis_test, [.-libdis_test]
