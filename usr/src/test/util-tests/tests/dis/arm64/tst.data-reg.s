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

	/* Data 1 Source */
	RBIT X9, X1
	RBIT WZR, W0
	REV16 X1, X30
	REV16 W3, WZR
	REV32 X6, X5
	REV32 XZR, X12
	REV W23, W3
	REV X4, X4
	CLZ W9, W9
	CLZ X12, XZR
	CLS W3, W25
	CLS X29, X28

	/* Data 2 Source */
	UDIV X12, XZR, X4
	UDIV W2, W4, WZR
	SDIV XZR, X1, X4
	SDIV W19, W0, W15
	LSLV X23, X24, X25
	LSLV W29, W30, W4
	LSRV X0, X3, X1
	LSRV W9, WZR, W29
	ASRV X3, X9, X10
	ASRV W3, W4, W8
	RORV X7, X2, X12
	RORV W7, W4, W3

	/* Logic - Shifted Regs */
	AND X24, X25, X26, LSL #62
	AND W14, W15, W16, LSR #20
	BIC X4, X5, X6, ASR #32
	BIC W1, W19, W22, ROR #2
	ORR X12, X13, X14, LSL #5
	ORR W1, W3, WZR, LSR #1
	ORN X1, X1, X1, ASR #5
	ORN W2, W2, W2, ROR #6
	EOR X7, XZR, X9, LSL #50
	EOR WZR, W1, W3, LSR #12
	EON X0, X2, X3, ASR #14
	EON W0, W2, W3, ROR #20
	ANDS X18, X12, X14, LSL #42
	ANDS W0, W2, W24, LSR #3
	BICS X1, X9, X19, ASR #1
	BICS W9, W4, W1, ROR #30

	/* Add/Sub Shifted Regs */
	ADD X24, X25, X26, LSL #62
	ADD W14, W15, W16, LSR #20
	ADDS X4, X5, X6, ASR #32
	ADDS W1, W19, W22, LSL #0
	SUB X12, X13, X14, LSR #5
	SUB W1, W3, WZR, ASR #1
	SUBS X1, XZR, X1, LSL #5
	SUBS W2, W2, W2, LSR #6

	/* Add/Sub Extended Regs */
	ADD X0, SP, W2, UXTB #0
	ADDS X30, X1, WZR, UXTH #1
	SUB X4, X12, W2, UXTW #2
	SUBS X3, X13, X5, UXTX #3
	ADD W5, W14, W2, SXTB #4
	ADDS W10, WSP, W2, SXTH #0
	SUB WSP, W23, W2, SXTW #1
	SUBS W9, W22, W10, SXTX #2

	ADD SP, X12, X1, LSL #2
	SUB WSP, W9, W8, LSL #2


	/* Add/Sub with Carry */
	ADC X9, X9, X10
	ADC W12, WZR, W19
	ADCS XZR, X1, X0
	ADCS W3, W4, WZR
	SBC X1, X2, X3
	SBC W3, W4, W5
	SBCS X9, X10, X11
	SBCS W20, W21, W22

	/*
	 * TODO:  conditional compare (reg/immediate),
	 * conditional select, 3 source data
	 */

.size libdis_test, [.-libdis_test]
