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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dis_arm64_decoder.h"
#include "libdisasm.h"
#include "libdisasm_impl.h"

#define	A64_FMT_BUFSIZE	1024
#define	A64_UXTW_OP	2
#define	A64_UXTX_OP	3

static const char *arm64_gp_regs_64[] = {
	"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10",
	"x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20",
	"x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
	"sp", "xzr",
};

static const char *arm64_gp_regs_32[] = {
	"w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10",
	"w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19", "w20",
	"w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30",
	"wsp", "wzr",
};

static const char *arm64_extension_names[] = {
	"uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx",
};

static const char *arm64_regindex_names[8] = {
	[0x2] = "uxtw",
	[0x3] = "lsl",
	[0x6] = "sxtw",
	[0x7] = "sxtx",
};

static const char *arm64_cond_code_names[] = {
	"eq",	/* 0000 */
	"ne",	/* 0001 */
	"cs",	/* 0010 aka "hs" */
	"cc",	/* 0011 aka "lo" */
	"mi",	/* 0100 */
	"pl",	/* 0101 */
	"vs",	/* 0110 */
	"vc",	/* 0111 */
	"hi",	/* 1000 */
	"ls",	/* 1001 */
	"ge",	/* 1010 */
	"lt",	/* 1011 */
	"gt",	/* 1100 */
	"le",	/* 1101 */
	"al",	/* 1110 */
	"nv",	/* 1111 */
};

static const char *arm64_barrier_op_names[] = {
	NULL,		/* 0000 */
	"oshld",	/* 0001 */
	"oshst",	/* 0010 */
	"osh",		/* 0011 */
	NULL,		/* 0100 */
	"nshld",	/* 0101 */
	"nshst",	/* 0110 */
	"nsh",		/* 0111 */
	NULL,		/* 1000 */
	"ishld",	/* 1001 */
	"ishst",	/* 1010 */
	"ish",		/* 1011 */
	NULL,		/* 1100 */
	"ld",		/* 1101 */
	"st",		/* 1110 */
	"sy",		/* 1111 */
};

static const char *arm64_pstatefield_names[64] = {
	[0x5] = "spsel",	/* op1:op2 = 000:101 */
	[0x1e] = "daifset",	/* op1:op2 = 011:110 */
	[0x1f] = "daifclr",	/* op1:op2 = 011:111 */
};


typedef struct arm64_sys_reg_entry {
	const char *a64_mnem;
	/*
	 * op0 isn't here since op0 == 2 means use the debug register list,
	 * otherwise use nondebug.
	 */
	uint8_t a64_cn;
	uint8_t a64_op1;
	uint8_t a64_cm;
	uint8_t a64_op2;
} arm64_sys_reg_entry_t;

static arm64_sys_reg_entry_t arm64_sys_reg_debug[] = {
	{"osdtrrx_el1",		0,	0,	0,	2},
	{"mdccint_el1",		0,	0,	2,	0},
	{"mdscr_el1",		0,	0,	2,	2},
	{"osdtrtx_el1",		0,	0,	3,	2},
	{"oseccr_el1",		0,	0,	6,	2},
	{"dbgbvr0_el1",		0,	0,	0,	4},
	{"dbgbvr1_el1",		0,	0,	1,	4},
	{"dbgbvr2_el1",		0,	0,	2,	4},
	{"dbgbvr3_el1",		0,	0,	3,	4},
	{"dbgbvr4_el1",		0,	0,	4,	4},
	{"dbgbvr5_el1",		0,	0,	5,	4},
	{"dbgbvr6_el1",		0,	0,	6,	4},
	{"dbgbvr7_el1",		0,	0,	7,	4},
	{"dbgbvr8_el1",		0,	0,	8,	4},
	{"dbgbvr9_el1",		0,	0,	9,	4},
	{"dbgbvr10_el1",	0,	0,	10,	4},
	{"dbgbvr11_el1",	0,	0,	11,	4},
	{"dbgbvr12_el1",	0,	0,	12,	4},
	{"dbgbvr13_el1",	0,	0,	13,	4},
	{"dbgbvr14_el1",	0,	0,	14,	4},
	{"dbgbvr15_el1",	0,	0,	15,	4},
	{"dbgbcr0_el1",		0,	0,	0,	5},
	{"dbgbcr1_el1",		0,	0,	1,	5},
	{"dbgbcr2_el1",		0,	0,	2,	5},
	{"dbgbcr3_el1",		0,	0,	3,	5},
	{"dbgbcr4_el1",		0,	0,	4,	5},
	{"dbgbcr5_el1",		0,	0,	5,	5},
	{"dbgbcr6_el1",		0,	0,	6,	5},
	{"dbgbcr7_el1",		0,	0,	7,	5},
	{"dbgbcr8_el1",		0,	0,	8,	5},
	{"dbgbcr9_el1",		0,	0,	9,	5},
	{"dbgbcr10_el1",	0,	0,	10,	5},
	{"dbgbcr11_el1",	0,	0,	11,	5},
	{"dbgbcr12_el1",	0,	0,	12,	5},
	{"dbgbcr13_el1",	0,	0,	13,	5},
	{"dbgbcr14_el1",	0,	0,	14,	5},
	{"dbgbcr15_el1",	0,	0,	15,	5},
	{"dbgwvr0_el1",		0,	0,	0,	6},
	{"dbgwvr1_el1",		0,	0,	1,	6},
	{"dbgwvr2_el1",		0,	0,	2,	6},
	{"dbgwvr3_el1",		0,	0,	3,	6},
	{"dbgwvr4_el1",		0,	0,	4,	6},
	{"dbgwvr5_el1",		0,	0,	5,	6},
	{"dbgwvr6_el1",		0,	0,	6,	6},
	{"dbgwvr7_el1",		0,	0,	7,	6},
	{"dbgwvr8_el1",		0,	0,	8,	6},
	{"dbgwvr9_el1",		0,	0,	9,	6},
	{"dbgwvr10_el1",	0,	0,	10,	6},
	{"dbgwvr11_el1",	0,	0,	11,	6},
	{"dbgwvr12_el1",	0,	0,	12,	6},
	{"dbgwvr13_el1",	0,	0,	13,	6},
	{"dbgwvr14_el1",	0,	0,	14,	6},
	{"dbgwvr15_el1",	0,	0,	15,	6},
	{"dbgwcr0_el1",		0,	0,	0,	7},
	{"dbgwcr1_el1",		0,	0,	1,	7},
	{"dbgwcr2_el1",		0,	0,	2,	7},
	{"dbgwcr3_el1",		0,	0,	3,	7},
	{"dbgwcr4_el1",		0,	0,	4,	7},
	{"dbgwcr5_el1",		0,	0,	5,	7},
	{"dbgwcr6_el1",		0,	0,	6,	7},
	{"dbgwcr7_el1",		0,	0,	7,	7},
	{"dbgwcr8_el1",		0,	0,	8,	7},
	{"dbgwcr9_el1",		0,	0,	9,	7},
	{"dbgwcr10_el1",	0,	0,	10,	7},
	{"dbgwcr11_el1",	0,	0,	11,	7},
	{"dbgwcr12_el1",	0,	0,	12,	7},
	{"dbgwcr13_el1",	0,	0,	13,	7},
	{"dbgwcr14_el1",	0,	0,	14,	7},
	{"dbgwcr15_el1",	0,	0,	15,	7},
	{"mdrar_el1",		1,	0,	0,	0},
	{"oslar_el1",		1,	0,	0,	4},
	{"oslsr_el1",		1,	0,	1,	4},
	{"osdlr_el1",		1,	0,	3,	4},
	{"dbgprcr_el1",		1,	0,	4,	4},
	{"dbgclaimset_el1",	7,	0,	8,	6},
	{"dbgclaimclr_el1",	7,	0,	9,	6},
	{"dbgauthstatus_el1",	7,	0,	14,	6},
	{"mdccsr_el0",		0,	3,	1,	0},
	{"dbgdtr_el0",		0,	3,	4,	0},
	{"dbgdtrrx_el0",	0,	3,	5,	0},
	{"dbgvcr32_el2",	0,	4,	7,	0},
	/* AArch32 Execution environment registers */
	{"teecr32_el1",		0,	2,	0,	0},
	{"teehbr32_el1",	1,	2,	0,	0},
	{NULL,			0,	0,	0,	0}
	/* NULL terminate to give an end when looping through array */
};

static arm64_sys_reg_entry_t arm64_sys_reg_nondebug[] = {
	{"midr_el1",		0,	0,	0,	0},
	{"mpidr_el1",		0,	0,	0,	5},
	{"revidr_el1",		0,	0,	0,	6},
	{"id_pfr0_el1",		0,	0,	1,	0},
	{"id_pfr1_el1",		0,	0,	1,	1},
	{"id_dfr0_el1",		0,	0,	1,	2},
	{"id_afr0_el1",		0,	0,	1,	3},
	{"id_mmfr0_el1",	0,	0,	1,	4},
	{"id_mmfr1_el1",	0,	0,	1,	5},
	{"id_mmfr2_el1",	0,	0,	1,	6},
	{"id_mmfr3_el1",	0,	0,	1,	7},
	{"id_isar0_el1",	0,	0,	2,	0},
	{"id_isar1_el1",	0,	0,	2,	1},
	{"id_isar2_el1",	0,	0,	2,	2},
	{"id_isar3_el1",	0,	0,	2,	3},
	{"id_isar4_el1",	0,	0,	2,	4},
	{"id_isar5_el1",	0,	0,	2,	5},
	{"id_mmfr4_el1",	0,	0,	2,	6},
	{"mvfr0_el1",		0,	0,	3,	0},
	{"mvfr1_el1",		0,	0,	3,	1},
	{"mvfr2_el1",		0,	0,	3,	2},
	{"id_aa64pfr0_el1",	0,	0,	4,	0},
	{"id_aa64pfr1_el1",	0,	0,	4,	1},
	{"id_aa64dfr0_el1",	0,	0,	5,	0},
	{"id_aa64dfr1_el1",	0,	0,	5,	1},
	{"id_aa64afr0_el1",	0,	0,	5,	4},
	{"id_aa64afr1_el1",	0,	0,	5,	5},
	{"id_aa64isar0_el1",	0,	0,	6,	0},
	{"id_aa64isar1_el1",	0,	0,	6,	1},
	{"id_aa64mmfr0_el1",	0,	0,	7,	0},
	{"id_aa64mmfr1_el1",	0,	0,	7,	1},
	{"ccsidr_el1",		0,	1,	0,	0},
	{"clidr_el1",		0,	1,	0,	1},
	{"aidr_el1",		0,	1,	0,	7},
	{"csselr_el1",		0,	2,	0,	0},
	{"ctr_el0",		0,	3,	0,	1},
	{"dczid_el0",		0,	3,	0,	7},
	{"vpidr_el2",		0,	4,	0,	0},
	{"vmpidr_el2",		0,	4,	0,	5},
	{"sctlr_el1",		1,	0,	0,	0},
	{"actlr_el1",		1,	0,	0,	1},
	{"cpacr_el1",		1,	0,	0,	2},
	{"sctlr_el2",		1,	4,	0,	0},
	{"actlr_el2",		1,	4,	0,	1},
	{"hcr_el2",		1,	4,	1,	0},
	{"mdcr_el2",		1,	4,	1,	1},
	{"cptr_el2",		1,	4,	1,	2},
	{"hstr_el2",		1,	4,	1,	3},
	{"hacr_el2",		1,	4,	1,	7},
	{"sctlr_el3",		1,	6,	0,	0},
	{"actlr_el3",		1,	6,	0,	1},
	{"scr_el3",		1,	6,	1,	0},
	{"sder32_el3",		1,	6,	1,	1},
	{"cptr_el3",		1,	6,	1,	2},
	{"mdcr_el3",		1,	6,	3,	1},
	{"ttbr0_el1",		2,	0,	0,	0},
	{"ttbr1_el1",		2,	0,	0,	1},
	{"tcr_el1",		2,	0,	0,	2},
	{"ttbr0_el2",		2,	4,	0,	0},
	{"tcr_el2",		2,	4,	0,	2},
	{"vttbr_el2",		2,	4,	1,	0},
	{"vtcr_el2",		2,	4,	1,	2},
	{"ttbr0_el3",		2,	6,	0,	0},
	{"tcr_el3",		2,	6,	0,	2},
	{"dacr32_el2",		3,	4,	0,	0},
	{"spsr_el1",		4,	0,	0,	0},
	{"elr_el1",		4,	0,	0,	1},
	{"sp_el0",		4,	0,	1,	0},
	{"spsel",		4,	0,	2,	0},
	{"currentel",		4,	0,	2,	2},
	{"nzcv",		4,	3,	2,	0},
	{"daif",		4,	3,	2,	1},
	{"fpcr",		4,	3,	4,	0},
	{"fpsr",		4,	3,	4,	1},
	{"dspsr_el0",		4,	3,	5,	0},
	{"dlr_el0",		4,	3,	5,	1},
	{"spsr_el2",		4,	4,	0,	0},
	{"elr_el2",		4,	4,	0,	1},
	{"sp_el1",		4,	4,	1,	0},
	{"spsr_irq",		4,	4,	3,	0},
	{"spsr_abt",		4,	4,	3,	1},
	{"spsr_und",		4,	4,	3,	2},
	{"spsr_fiq",		4,	4,	3,	3},
	{"spsr_el3",		4,	6,	0,	0},
	{"elr_el3",		4,	6,	0,	1},
	{"sp_el2",		4,	6,	1,	0},
	{"ifsr32_el2",		5,	4,	0,	1},
	{"fpexc32_el2",		5,	4,	3,	0},
	{"afsr0_el1",		5,	0,	1,	0},
	{"afsr1_el1",		5,	0,	1,	1},
	{"esr_el1",		5,	0,	2,	0},
	{"afsr0_el2",		5,	4,	1,	0},
	{"afsr1_el2",		5,	4,	1,	1},
	{"esr_el2",		5,	4,	2,	0},
	{"afsr0_el3",		5,	6,	1,	0},
	{"afsr1_el3",		5,	6,	1,	1},
	{"esr_el3",		5,	6,	2,	0},
	{"far_el1",		6,	0,	0,	0},
	{"far_el2",		6,	4,	0,	0},
	{"hpfar_el2",		6,	4,	0,	4},
	{"far_el3",		6,	6,	0,	0},
	{"par_el1",		7,	0,	4,	0},
	{"pmintenset_el1",	9,	0,	14,	1},
	{"pmintenclr_el1",	9,	0,	14,	2},
	{"pmcr_el0",		9,	3,	12,	0},
	{"pmcntenset_el0",	9,	3,	12,	1},
	{"pmcntenclr_el0",	9,	3,	12,	2},
	{"pmovsclr_el0",	9,	3,	12,	3},
	{"pmswinc_el0",		9,	3,	12,	4},
	{"pmselr_el0",		9,	3,	12,	5},
	{"pmceid0_el0",		9,	3,	12,	6},
	{"pmceid1_el0",		9,	3,	12,	7},
	{"pmccntr_el0",		9,	3,	13,	0},
	{"pmxevtyper_el0",	9,	3,	13,	1},
	{"pmxevcntr_el0",	9,	3,	13,	2},
	{"pmuserenr_el0",	9,	3,	14,	0},
	{"pmovsset_el0",	9,	3,	14,	3},
	{"mair_el1",		10,	0,	2,	0},
	{"amair_el1",		10,	0,	3,	0},
	{"mair_el2",		10,	4,	2,	0},
	{"amair_el2",		10,	4,	3,	0},
	{"mair_el3",		10,	6,	2,	0},
	{"amair_el3",		10,	6,	3,	0},
	{"vbar_el1",		12,	0,	0,	0},
	{"rvbar_el1",		12,	0,	0,	1},
	{"rmr_el1",		12,	0,	0,	2},
	{"isr_el1",		12,	0,	1,	0},
	{"vbar_el2",		12,	4,	0,	0},
	{"rvbar_el2",		12,	4,	0,	1},
	{"rmr_el2",		12,	4,	0,	2},
	{"vbar_el3",		12,	6,	0,	0},
	{"rvbar_el3",		12,	6,	0,	1},
	{"rmr_el3",		12,	6,	0,	2},
	{"contextidr_el1",	13,	0,	0,	1},
	{"tpidr_el1",		13,	0,	0,	4},
	{"tpidr_el0",		13,	3,	0,	2},
	{"tpidrro_el0",		13,	3,	0,	3},
	{"tpidr_el2",		13,	4,	0,	2},
	{"tpidr_el3",		13,	6,	0,	2},
	{"cntkctl_el1",		14,	0,	1,	0},
	{"cntfrq_el0",		14,	3,	0,	0},
	{"cntpct_el0",		14,	3,	0,	1},
	{"cntvct_el0",		14,	3,	0,	2},
	{"cntp_tval_el0",	14,	3,	2,	0},
	{"cntp_ctl_el0",	14,	3,	2,	1},
	{"cntp_cval_el0",	14,	3,	2,	2},
	{"cntv_tval_el0",	14,	3,	3,	0},
	{"cntv_ctl_el0",	14,	3,	3,	1},
	{"cntv_cval_el0",	14,	3,	3,	2},
	{"cnthctl_el2",		14,	4,	1,	0},
	{"cnthp_tval_el2",	14,	4,	2,	0},
	{"cnthp_ctl_el2",	14,	4,	2,	1},
	{"cnthp_cval_el2",	14,	4,	2,	2},
	{"cntvoff_el2",		14,	4,	0,	3},
	{"cntps_tval_el1",	14,	7,	2,	0},
	{"cntps_ctl_el1",	14,	7,	2,	1},
	{"cntps_cval_el1",	14,	7,	2,	2},
	{"pmevcntr0_el0",	14,	3,	8,	0},
	{"pmevcntr1_el0",	14,	3,	8,	1},
	{"pmevcntr2_el0",	14,	3,	8,	2},
	{"pmevcntr3_el0",	14,	3,	8,	3},
	{"pmevcntr4_el0",	14,	3,	8,	4},
	{"pmevcntr5_el0",	14,	3,	8,	5},
	{"pmevcntr6_el0",	14,	3,	8,	6},
	{"pmevcntr7_el0",	14,	3,	8,	7},
	{"pmevcntr8_el0",	14,	3,	9,	0},
	{"pmevcntr9_el0",	14,	3,	9,	1},
	{"pmevcntr10_el0",	14,	3,	9,	2},
	{"pmevcntr11_el0",	14,	3,	9,	3},
	{"pmevcntr12_el0",	14,	3,	9,	4},
	{"pmevcntr13_el0",	14,	3,	9,	5},
	{"pmevcntr14_el0",	14,	3,	9,	6},
	{"pmevcntr15_el0",	14,	3,	9,	7},
	{"pmevcntr16_el0",	14,	3,	10,	0},
	{"pmevcntr17_el0",	14,	3,	10,	1},
	{"pmevcntr18_el0",	14,	3,	10,	2},
	{"pmevcntr19_el0",	14,	3,	10,	3},
	{"pmevcntr20_el0",	14,	3,	10,	4},
	{"pmevcntr21_el0",	14,	3,	10,	5},
	{"pmevcntr22_el0",	14,	3,	10,	6},
	{"pmevcntr23_el0",	14,	3,	10,	7},
	{"pmevcntr24_el0",	14,	3,	11,	0},
	{"pmevcntr25_el0",	14,	3,	11,	1},
	{"pmevcntr26_el0",	14,	3,	11,	2},
	{"pmevcntr27_el0",	14,	3,	11,	3},
	{"pmevcntr28_el0",	14,	3,	11,	4},
	{"pmevcntr29_el0",	14,	3,	11,	5},
	{"pmevcntr30_el0",	14,	3,	11,	6},
	{"pmevtyper0_el0",	14,	3,	12,	0},
	{"pmevtyper1_el0",	14,	3,	12,	1},
	{"pmevtyper2_el0",	14,	3,	12,	2},
	{"pmevtyper3_el0",	14,	3,	12,	3},
	{"pmevtyper4_el0",	14,	3,	12,	4},
	{"pmevtyper5_el0",	14,	3,	12,	5},
	{"pmevtyper6_el0",	14,	3,	12,	6},
	{"pmevtyper7_el0",	14,	3,	12,	7},
	{"pmevtyper8_el0",	14,	3,	13,	0},
	{"pmevtyper9_el0",	14,	3,	13,	1},
	{"pmevtyper10_el0",	14,	3,	13,	2},
	{"pmevtyper11_el0",	14,	3,	13,	3},
	{"pmevtyper12_el0",	14,	3,	13,	4},
	{"pmevtyper13_el0",	14,	3,	13,	5},
	{"pmevtyper14_el0",	14,	3,	13,	6},
	{"pmevtyper15_el0",	14,	3,	13,	7},
	{"pmevtyper16_el0",	14,	3,	14,	0},
	{"pmevtyper17_el0",	14,	3,	14,	1},
	{"pmevtyper18_el0",	14,	3,	14,	2},
	{"pmevtyper19_el0",	14,	3,	14,	3},
	{"pmevtyper20_el0",	14,	3,	14,	4},
	{"pmevtyper21_el0",	14,	3,	14,	5},
	{"pmevtyper22_el0",	14,	3,	14,	6},
	{"pmevtyper23_el0",	14,	3,	14,	7},
	{"pmevtyper24_el0",	14,	3,	15,	0},
	{"pmevtyper25_el0",	14,	3,	15,	1},
	{"pmevtyper26_el0",	14,	3,	15,	2},
	{"pmevtyper27_el0",	14,	3,	15,	3},
	{"pmevtyper28_el0",	14,	3,	15,	4},
	{"pmevtyper29_el0",	14,	3,	15,	5},
	{"pmevtyper30_el0",	14,	3,	15,	6},
	{"pmccfiltr_el0",	14,	3,	15,	7},
	{NULL,			0,	0,	0,	0}
	/* NULL terminate to give an end when looping through array */
};

static const char *arm64_prefetch_ops_names[32] = {
	[0x0] = "pldl1keep",
	[0x1] = "pldl1strm",
	[0x2] = "pldl2keep",
	[0x3] = "pldl2strm",
	[0x4] = "pldl3keep",
	[0x5] = "pldl3strm",
	[0x8] = "plil1keep",
	[0x9] = "plil1strm",
	[0xa] = "plil2keep",
	[0xb] = "plil2strm",
	[0xc] = "plil3keep",
	[0xd] = "plil3strm",
	[0x10] = "pstl1keep",
	[0x11] = "pstl1strm",
	[0x12] = "pstl2keep",
	[0x13] = "pstl2strm",
	[0x14] = "pstl3keep",
	[0x15] = "pstl3strm",
};

static void
arm64_format_named_sysreg(arm64ins_t *x, uint8_t ind, char *buf, size_t buflen)
{
	arm64_opnd_t *opnd = &x->a64_opnds[ind];
	arm64_sys_reg_t *sys_reg = &opnd->a64_value.sys_reg;
	arm64_sys_reg_entry_t *sys_ent;

	/* op0 determines whether to use debug or nondebug array */
	if (sys_reg->a64_op0 == 2) {
		sys_ent = arm64_sys_reg_debug;
	} else {
		sys_ent = arm64_sys_reg_nondebug;
	}

	/* Then use the rest of the opcodes to determine which entry to use */
	for (; sys_ent->a64_mnem != NULL; sys_ent++) {
		if (sys_ent->a64_op1 == sys_reg->a64_op1 && sys_ent->a64_cn ==
		    sys_reg->a64_cn && sys_ent->a64_cm == sys_reg->a64_cm &&
		    sys_ent->a64_op2 == sys_reg->a64_op2) {
			break;
		}
	}

	if (sys_ent->a64_mnem != NULL) {
		(void) snprintf(buf, buflen, sys_ent->a64_mnem);
	} else {
		/* For sysregs without a name, print them the standard way: */
		(void) snprintf(buf, buflen, "s%u_%u_c%u_c%u_%u",
		    sys_reg->a64_op0, sys_reg->a64_op1, sys_reg->a64_cn,
		    sys_reg->a64_cm, sys_reg->a64_op2);
	}
}


static void
arm64_format_extension(arm64ins_t *x, uint8_t ind, char *buf, size_t buflen)
{
	const char *mnem;
	arm64_opnd_t *opnd = &x->a64_opnds[ind];
	uint64_t extension_op = opnd->a64_value.u_val;
	uint8_t rn_val = x->a64_opnds[0].a64_value.u_val;

	assert(extension_op < 8 && rn_val < 32);
	mnem = arm64_extension_names[extension_op];

	if (rn_val == A64_SP_REG) {
		/*
		 * When rn_val is the SP, the extensions take on
		 * slightly different mnemonics based on bitsize
		 */
		uint64_t compare_to = (opnd->a64_bitsize == A64_64BIT) ?
		    A64_UXTX_OP : A64_UXTW_OP;
		if (extension_op == compare_to) {
			mnem = "lsl";
		}
	}
	(void) snprintf(buf, buflen, "%s #%u", mnem, opnd->a64_base);
}

static void
arm64_format_regindex(arm64ins_t *x, uint8_t ind, char *buf, size_t buflen)
{
	int buf_off = 0;
	arm64_opnd_t *opnd = &x->a64_opnds[ind];
	arm64_mem_reg_t *mem_reg = &opnd->a64_value.mem_reg;
	const char *ext_name;

	/*
	 * Reg index mem locations are generally displayed in the form:
	 * [<Xn|Sp>, (<Wm>|<Xm>){, <operation> {<amount>}}]
	 *
	 * The operation is not displayed when op = LSL = 0x3 and amount = 0
	 * The amount is not displayed when amount = 0
	 */

	/* Start with "[<Xn|Sp>," */
	assert(opnd->a64_base < 32);
	buf_off += snprintf(buf + buf_off, buflen - buf_off, "[%s, ",
	    arm64_gp_regs_64[opnd->a64_base]);

	/* Next the register to index to */
	assert(mem_reg->a64_reg < 32);

	/*
	 * Similar to how we print A64_GP_REG, when the reg is 31, we increase
	 * it by 1 to switch it from SP/WSP to XZR/WZR as the operand requires
	 */
	if (mem_reg->a64_reg == A64_SP_REG) {
		mem_reg->a64_reg++;
	}
	if (mem_reg->a64_regsize == A64_32BIT) {
		buf_off += snprintf(buf + buf_off, buflen - buf_off, "%s",
		    arm64_gp_regs_32[mem_reg->a64_reg]);
	} else {
		buf_off += snprintf(buf + buf_off, buflen - buf_off, "%s",
		    arm64_gp_regs_64[mem_reg->a64_reg]);
	}

	/* Next Extension/shift operation, which isn't always displayed */
	if (mem_reg->a64_display_op) {
		/* Decoder guaruntees these instructions are valid, so assert */
		assert(mem_reg->a64_ext_op < 8);
		ext_name = arm64_regindex_names[mem_reg->a64_ext_op];
		assert(ext_name != NULL);
		buf_off += snprintf(buf + buf_off, buflen - buf_off, ", %s",
		    ext_name);

		/* After displaying the op, display immediate if we should */
		if (mem_reg->a64_display_imm) {
			buf_off += snprintf(buf + buf_off, buflen - buf_off,
			    " #%u", mem_reg->a64_ext_imm);
		}
	}

	/* Lastly, close the square brackets off */
	buf_off += snprintf(buf + buf_off, buflen - buf_off, "]");
}

static void
arm64_format_label(arm64ins_t *x, uint8_t ind, char *buf, size_t buflen,
    dis_handle_t *dhp)
{
	char label_buf[A64_FMT_BUFSIZE];
	size_t label_len = sizeof (label_buf);
	arm64_opnd_t *opnd = &x->a64_opnds[ind];
	int64_t offset = opnd->a64_value.u_val - x->a64_pc;

	/* Load the symbol */
	(void) dhp->dh_lookup(dhp->dh_data, opnd->a64_value.u_val,
	    label_buf, label_len, NULL, NULL);

	/* Print the PC offset then the symbol name */
	if (offset >= 0) {
		(void) snprintf(buf, buflen, "+0x%llx \t<%s>", offset,
		    label_buf);
	} else {
		(void) snprintf(buf, buflen, "-0x%llx \t<%s>", -offset,
		    label_buf);
	}
}

static void
arm64_format_opnd(arm64ins_t *x, uint8_t ind, char *buf, size_t buflen,
    dis_handle_t *dhp)
{
	char fmt_buf[A64_FMT_BUFSIZE];
	size_t fmt_len = sizeof (fmt_buf);
	arm64_opnd_t *opnd = &x->a64_opnds[ind];

	if (ind != 0) {
		(void) strlcat(buf, ", ", buflen);
	} else {
		(void) strlcat(buf, " ", buflen);
	}
	(void) memset(fmt_buf, 0, fmt_len);

	switch (opnd->a64_type) {
	case A64_GP_REG:
		/*
		 * The difference between A64_GP_REG and A64_GP_REG_SP is that
		 * register 31 is XZR/WZR for GP_REG and SP/WSP for GP_REG_SP.
		 * So, we can use the same string arrays for both types by
		 * shifting register 31 in the GP_REG case up by 1 and then
		 * falling through.
		 */
		if (opnd->a64_value.u_val == A64_SP_REG) {
			opnd->a64_value.u_val++;
		}
		/* FALLTHROUGH */
	case A64_GP_REG_SP:
		assert(opnd->a64_value.u_val <= 32);
		if (opnd->a64_bitsize == A64_32BIT) {
			(void) snprintf(fmt_buf, fmt_len, "%s",
			    arm64_gp_regs_32[opnd->a64_value.u_val]);
		} else {
			(void) snprintf(fmt_buf, fmt_len, "%s",
			    arm64_gp_regs_64[opnd->a64_value.u_val]);
		}
		break;
	case A64_LABEL:
		arm64_format_label(x, ind, fmt_buf, fmt_len, dhp);
		break;
	/* For now, implement prefetch options as an imm. and fallthrough */
	case A64_PREFETCH_OPTIONS:
		if (arm64_prefetch_ops_names[opnd->a64_value.u_val] != NULL) {
			(void) snprintf(fmt_buf, fmt_len, "%s",
			    arm64_prefetch_ops_names[opnd->a64_value.u_val]);
		} else {
			(void) snprintf(fmt_buf, fmt_len, "#0x%x",
			    opnd->a64_value.u_val);
		}
		break;
	case A64_IMMEDIATE:
		(void) snprintf(fmt_buf, fmt_len, "#0x%llx",
		    opnd->a64_value.u_val);
		break;
	case A64_LEFT_SHIFT:
		(void) snprintf(fmt_buf, fmt_len, "lsl #%llu",
		    opnd->a64_value.u_val);
		break;
	case A64_RIGHT_SHIFT_LOG:
		(void) snprintf(fmt_buf, fmt_len, "lsr #%llu",
		    opnd->a64_value.u_val);
		break;
	case A64_RIGHT_SHIFT_ARITHM:
		(void) snprintf(fmt_buf, fmt_len, "asr #%llu",
		    opnd->a64_value.u_val);
		break;
	case A64_ROTATE_SHIFT:
		(void) snprintf(fmt_buf, fmt_len, "ror #%llu",
		    opnd->a64_value.u_val);
		break;
	case A64_PRE_INDEX:
		assert(opnd->a64_base <= 32);
		(void) snprintf(fmt_buf, fmt_len, "[%s, #%lld]!",
		    arm64_gp_regs_64[opnd->a64_base], opnd->a64_value.s_val);
		break;
	case A64_POST_INDEX:
		assert(opnd->a64_base <= 32);
		(void) snprintf(fmt_buf, fmt_len, "[%s], #%lld",
		    arm64_gp_regs_64[opnd->a64_base], opnd->a64_value.s_val);
		break;
	case A64_SIGNED_OFF:
		assert(opnd->a64_base <= 32);
		if (opnd->a64_value.s_val != 0) {
			(void) snprintf(fmt_buf, fmt_len, "[%s, #%lld]",
			    arm64_gp_regs_64[opnd->a64_base],
			    opnd->a64_value.s_val);
		} else {
			(void) snprintf(fmt_buf, fmt_len, "[%s]",
			    arm64_gp_regs_64[opnd->a64_base]);
		}
		break;
	case A64_REG_INDEX:
		arm64_format_regindex(x, ind, fmt_buf, fmt_len);
		break;
	case A64_CONDITION:
		assert(opnd->a64_value.u_val < 16);
		(void) snprintf(fmt_buf, fmt_len, "%s",
		    arm64_cond_code_names[opnd->a64_value.u_val]);
		break;
	case A64_EXTENSION:
		arm64_format_extension(x, ind, fmt_buf, fmt_len);
		break;
	case A64_FLAGS_STATE:
		/* TODO: not sure how to print these */
		(void) snprintf(fmt_buf, fmt_len, "#0x%llx",
		    opnd->a64_value.u_val);
		break;
	case A64_BARRIER_OP:
		assert(opnd->a64_value.u_val < 16);
		if (arm64_barrier_op_names[opnd->a64_value.u_val] != NULL) {
			(void) snprintf(fmt_buf, fmt_len,
			    arm64_barrier_op_names[opnd->a64_value.u_val]);
		} else {
			/*
			 * Only some barrier values are named, rest are printed
			 * as immediates.
			 */
			(void) snprintf(fmt_buf, fmt_len, "#0x%llx",
			    opnd->a64_value.u_val);
		}
		break;
	case A64_SYS_UNNAMED_REG:
		(void) snprintf(fmt_buf, fmt_len, "c%llu",
		    opnd->a64_value.u_val);
		break;
	case A64_SYS_NAMED_REG:
		arm64_format_named_sysreg(x, ind, fmt_buf, fmt_len);
		break;
	case A64_PSTATEFIELD:
		assert(arm64_pstatefield_names[opnd->a64_value.u_val]);
		(void) snprintf(fmt_buf, fmt_len, "%s",
		    arm64_pstatefield_names[opnd->a64_value.u_val]);
		break;
	default:
		(void) snprintf(fmt_buf, fmt_len, "OPND ERR");
		break;
	}

	(void) strlcat(buf, fmt_buf, buflen);
}

void
arm64_format_instr(arm64ins_t *x, char *buf, size_t buflen, dis_handle_t *dhp)
{
	uint8_t i;
	(void) snprintf(buf, buflen, "%s", x->a64_mnem);

	for (i = 0; i < x->a64_num_opnds; i++) {
		arm64_format_opnd(x, i, buf, buflen, dhp);
	}
}
