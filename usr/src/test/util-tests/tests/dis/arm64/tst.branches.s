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
.type libdis_test, %function
libdis_test:
	/* Branch (conditional) */
	B.EQ branch_target
	B.NE branch_target
	B.CS branch_target
	B.CC branch_target
	B.MI branch_target
	B.PL branch_target
	B.VS branch_target
	B.VC branch_target
	B.HI branch_target
	B.LS branch_target
	B.GE branch_target
	B.LT branch_target
	B.GT branch_target
	B.LE branch_target
	B.AL branch_target
	B.NV branch_target

	/* Unconditional Branch (register) */
	BR X0
	BR XZR
	BLR X19
	RET /* Defaults to X30 */
	RET X9
	ERET
	DRPS

	/* Unconditional Branch (immediate) */
	B branch_target
	BL branch_target

	/* Compare and Branch (immediate) */
	CBZ W19, branch_target
	CBZ XZR, branch_target
	CBNZ W3, branch_target
	CBNZ X2, branch_target

	/* Test and Branch (immediate) */
	TBZ WZR, #19, branch_target
	TBZ X24, #35, branch_target
	TBNZ W4, #2, branch_target
	TBNZ X16, #62, branch_target

	branch_target: ADD X0, X0, X0
.size libdis_test, [.-libdis_test]

