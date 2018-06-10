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
#include <string.h>

#include "dis_arm64_decoder.h"


/* Group code mask - first level of decoding */
#define	A64_GC_MASK	0x1e000000 /* bits 28:25 */
#define	A64_GC_SHIFT	25

#define	A64_GC_DATA_IMM_MASK	0xe
#define	A64_GC_LOAD_STORE_MASK	0x5
#define	A64_GC_MISC_MASK	0xe
#define	A64_GC_DATA_REG_MASK	0x7
#define	A64_GC_DATA_ADV_MASK	0x7

#define	A64_GC_DATA_IMM		0x8
#define	A64_GC_LOAD_STORE	0x4
#define	A64_GC_MISC		0xa
#define	A64_GC_DATA_REG		0x5
#define	A64_GC_DATA_ADV		0x7


#define	A64_PAGE_MASK	0xfff /* first 12 bits */

#define	A64_32BIT_MASK	0xffffffff

static uint64_t
arm64_ones(uint8_t len)
{
	assert(len <= 64);

	if (len == 64) {
		/*
		 * Shifting by the length is undefined, but ones(64) is
		 * a defined operation, so return all 1's
		 */
		return (~0ULL);
	}
	return ((1ULL << len) - 1);
}

static uint32_t
arm64_instr_extract_bits(uint32_t instr, uint8_t hibit, uint8_t lobit)
{
	uint32_t mask, bits;

	assert(hibit >= lobit && hibit < 32);

	/* Creates a mask with hibit - lobit + 1 "1"s. */
	mask = arm64_ones(hibit - lobit + 1) & A64_32BIT_MASK;
	mask = mask << lobit; /* Shifts mask to right positon */

	bits = instr & mask; /* Isolates the bits */
	return (bits >> lobit); /* Shift bits back to LSB */
}

static boolean_t
arm64_instr_extract_bit(uint32_t instr, uint8_t bit)
{
	return (arm64_instr_extract_bits(instr, bit, bit));
}

static int64_t
arm64_instr_extract_signed_num(uint32_t instr, uint8_t hibit, uint8_t lobit)
{
	boolean_t sign_bit;
	uint8_t num_1s, num_bits;
	uint32_t bits;
	uint64_t mask;
	int64_t ret;

	bits = arm64_instr_extract_bits(instr, hibit, lobit);
	sign_bit = arm64_instr_extract_bit(instr, hibit);

	/* Create a mask of all 1s on all higher bits not used by the number */
	num_bits = (hibit - lobit + 1);
	num_1s = sizeof (int64_t) * 8 - num_bits;
	mask = arm64_ones(num_1s) << num_bits;

	/*
	 * If this number is negative, sign extend it, otherwise
	 * ensure the MSB's are 0 by inverting the mask
	 */
	ret = sign_bit ? (bits | mask) : (bits & ~mask);
	return (ret);
}

static void
arm64_extract_unnamed_sys_reg(arm64ins_t *x, uint8_t hibit, uint8_t lobit)
{
	uint8_t ind = x->a64_num_opnds;
	uint8_t reg = arm64_instr_extract_bits(x->a64_instr, hibit, lobit);

	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = A64_SYS_UNNAMED_REG;
	x->a64_opnds[ind].a64_value.u_val = reg;
	x->a64_num_opnds++;
}

static void
arm64_extract_named_sys_reg(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t op0 = arm64_instr_extract_bits(instr, 19, 19) + 2;
	uint8_t op1 = arm64_instr_extract_bits(instr, 18, 16);
	uint8_t cn = arm64_instr_extract_bits(instr, 15, 12);
	uint8_t cm = arm64_instr_extract_bits(instr, 11, 8);
	uint8_t op2 = arm64_instr_extract_bits(instr, 7, 5);
	uint8_t ind = x->a64_num_opnds;

	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = A64_SYS_NAMED_REG;
	x->a64_opnds[ind].a64_value.sys_reg.a64_op0 = op0;
	x->a64_opnds[ind].a64_value.sys_reg.a64_op1 = op1;
	x->a64_opnds[ind].a64_value.sys_reg.a64_cn = cn;
	x->a64_opnds[ind].a64_value.sys_reg.a64_cm = cm;
	x->a64_opnds[ind].a64_value.sys_reg.a64_op2 = op2;
	x->a64_num_opnds++;
}

static void
arm64_extract_reg(arm64ins_t *x, uint8_t hibit, uint8_t lobit, arm64_opnd_size_t
    size, boolean_t with_sp)
{
	uint8_t ind = x->a64_num_opnds;
	uint8_t reg = arm64_instr_extract_bits(x->a64_instr, hibit, lobit);

	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = with_sp ? A64_GP_REG_SP : A64_GP_REG;
	x->a64_opnds[ind].a64_value.u_val = reg;
	x->a64_opnds[ind].a64_bitsize = size;
	x->a64_num_opnds++;
}

static void
arm64_extract_imm(arm64ins_t *x, uint8_t hibit, uint8_t lobit)
{
	uint8_t ind = x->a64_num_opnds;

	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = A64_IMMEDIATE;
	x->a64_opnds[ind].a64_value.u_val = arm64_instr_extract_bits(
	    x->a64_instr, hibit, lobit);
	x->a64_num_opnds++;
}

/*
 * Defined in the Arm v8 manual section J1.3 - Shared Pseudocode
 * Rotates rightwards a number (in) of len bits by shift.
 */
static uint64_t
arm64_ror(uint64_t in, uint8_t len, uint8_t shift)
{
	uint64_t res = in;
	uint8_t i;

	assert(len <= 64);

	for (i = 0; i < shift; i++) {
		/*
		 * For each shift, move the LSB (res & 1) to the MSB spot,
		 * and or that with all other bits shifted right by 1.
		 */
		res = ((res & 1) << (len - 1)) | (res >> 1);
	}

	return (res);
}

/*
 * Defined in the Arm v8 manual section J1.3 - shared/functions/common/ROR
 * Replicates a number (in) of len bits into 64 bits.
 */
static uint64_t
arm64_replicate(uint64_t in, uint8_t len)
{
	uint64_t res = 0;
	uint8_t i, num_repl;

	assert(len != 0 && len <= 64 && 64 % len == 0);

	num_repl = 64 / len;

	for (i = 0; i < num_repl; i++) {
		uint64_t shifted = in << (i * len);
		res |= shifted;
	}

	return (res);
}

/*
 * Defined in the Arm v8 manual section J1.1 -
 * aarch64/instrs/integer/bitmasks/DecodeBitMasks
 *
 * This decodes an immediate for logical operations (AND/ORR/EOR/ANDS).
 * The immediate, is encoded with 3 valeus - N, immr, and imms.
 *
 * The immediate is defined as a pattern, that is then replicated into 64
 * or 32 bit bitmask depending on the operation, though in this function we
 * assume 64 bit to then cutoff later.
 *
 * The pattern that is replicated is determined as follows:
 * - Calculate len the highest bit of N:~imms (starting at bit 0)
 * - Calculate S, which is imms up to len bits (ie if len is 4, imms[3:0])
 * - Calculate R, which is immr up to len bits
 * - Calculate ext_size, which is 1 << len
 * - Calculate pattern, which is made of S + 1 ones zero extended to ext_size
 * - Rotate pattern by R bits
 */
static uint64_t
arm64_decode_bitmasked_imm(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t N, imms, immr, len_input, len, len_mask, S, R, ext_size;
	uint64_t pattern, rotated, res;

	/* Extract numbers from instruction */
	N = arm64_instr_extract_bits(instr, 22, 22);
	imms = arm64_instr_extract_bits(instr, 15, 10);
	immr = arm64_instr_extract_bits(instr, 21, 16);

	/* Determine the length of the pattern */
	len_input = (N << 6) | (~imms & 0x3f);
	/*
	 * flsll calculates the highest set bit, but starts at 1 so subtract 1
	 * to be consistent with ARM's highestSetBit
	 */
	len = flsll(len_input) - 1;
	assert(len < 7); /* Since len_input is 7 bits */

	/* Get only the first len bits of imms and immr */
	len_mask = arm64_ones(len);
	S = imms & len_mask;
	R = immr & len_mask;

	/* Calculate the pattern, and rotate it */
	ext_size = 1 << len;
	pattern = arm64_ones(S + 1);
	rotated = arm64_ror(pattern, ext_size, R);

	/* Replicate the pattern into the full 64 bits */
	res = arm64_replicate(rotated, ext_size);
	return (res);
}

static void
arm64_extract_logical_imm(arm64ins_t *x, arm64_opnd_size_t opnd_size)
{
	uint64_t res;
	uint8_t ind;

	res = arm64_decode_bitmasked_imm(x);
	if (opnd_size == A64_32BIT) {
		res = res & A64_32BIT_MASK;
	}

	ind = x->a64_num_opnds;
	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = A64_IMMEDIATE;
	x->a64_opnds[ind].a64_value.u_val = res;
	x->a64_num_opnds++;
}

static void
arm64_extract_shifted_reg_shift(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t shift_type = arm64_instr_extract_bits(instr, 23, 22);
	uint8_t imm6 = arm64_instr_extract_bits(instr, 15, 10);
	arm64_opnd_type_t type;
	uint8_t ind;

	if (imm6 == 0) {
		/* No need to show a shift of 0 */
		return;
	}

	switch (shift_type) {
	case 0:
		type = A64_LEFT_SHIFT;
		break;
	case 1:
		type = A64_RIGHT_SHIFT_LOG;
		break;
	case 2:
		type = A64_RIGHT_SHIFT_ARITHM;
		break;
	case 3:
		type = A64_ROTATE_SHIFT;
		break;
	}

	ind = x->a64_num_opnds;
	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = type;
	x->a64_opnds[ind].a64_value.u_val = imm6;
	x->a64_num_opnds++;
}


static int
arm64_extract_shiftl_opnd(arm64ins_t *x, uint8_t hibit, uint8_t lobit,
    uint8_t multiplier, uint64_t max_value)
{
	uint8_t ind;
	uint64_t shamt = arm64_instr_extract_bits(x->a64_instr, hibit, lobit);
	shamt = shamt * multiplier;

	if (shamt > max_value) {
		/*
		 * Some instructions it is possible to extract a shift of
		 * 3*12 for example when only 0*12 and 1*12 are valid.
		 */
		return (-1);
	}

	/* Shift of 0 is meaningless to append, return instead */
	if (shamt == 0) {
		return (0);
	}

	ind = x->a64_num_opnds;
	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = A64_LEFT_SHIFT;
	x->a64_opnds[ind].a64_value.u_val = shamt;
	x->a64_num_opnds++;

	return (0);
}

static void
arm64_append_label(arm64ins_t *x, int64_t imm, uint64_t base)
{
	uint8_t ind = x->a64_num_opnds;
	uint64_t abs_value;
	uint64_t addr = base;

	/*
	 * Adding signed/unsigned ints of same rank (ie int64 and uint64),
	 * converts the signed int to an unsinged int then adds, which is
	 * not what we want. However, we need an unsigned result as an address.
	 * To work around this, we convert the signed immediate to
	 * its unsigned absolute value and either add or subtract.
	 */
	if (imm >= 0) {
		abs_value = imm;
		addr = addr + abs_value;
	} else {
		abs_value = -imm;
		addr = addr - abs_value;
	}

	assert(ind < A64_MAX_OPNDS);
	x->a64_opnds[ind].a64_type = A64_LABEL;
	x->a64_opnds[ind].a64_value.u_val = addr;
	x->a64_num_opnds++;
}

static void
arm64_extract_label(arm64ins_t *x, uint8_t hibit, uint8_t lobit,
    uint8_t multiplier)
{
	uint64_t addr = x->a64_pc;
	int64_t signed_imm = arm64_instr_extract_signed_num(x->a64_instr, hibit,
	    lobit);
	signed_imm = signed_imm * multiplier;

	arm64_append_label(x, signed_imm, addr);
}

static void
arm64_extract_adr_label(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint64_t addr = x->a64_pc;
	boolean_t op = arm64_instr_extract_bit(instr, 31);
	int64_t imm = arm64_instr_extract_signed_num(instr, 23, 5);
	uint8_t immlo = arm64_instr_extract_bits(instr, 30, 29);

	/* Immediate is encoded as immhi:immlo */
	imm = (imm << 2) + immlo;

	if (op) {
		/* Indicates ADRP, which means only use the pagenums */
		imm = imm << 12;
		addr = addr & ~A64_PAGE_MASK;
	}

	arm64_append_label(x, imm, addr);
}

static void
arm64_extract_flags_state(arm64ins_t *x, uint8_t hibit, uint8_t lobit)
{
	uint32_t state = arm64_instr_extract_bits(x->a64_instr, hibit, lobit);
	uint8_t ind = x->a64_num_opnds;

	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = A64_FLAGS_STATE;
	x->a64_opnds[ind].a64_value.u_val = state;
	x->a64_num_opnds++;
}

static void
arm64_extract_condition(arm64ins_t *x, uint8_t hibit, uint8_t lobit)
{
	uint8_t ind = x->a64_num_opnds;
	uint32_t cond = arm64_instr_extract_bits(x->a64_instr, hibit, lobit);

	assert(ind < A64_MAX_OPNDS);

	x->a64_opnds[ind].a64_type = A64_CONDITION;
	x->a64_opnds[ind].a64_value.u_val = cond;
	x->a64_num_opnds++;
}

static void
arm64_extract_mem_loc(arm64ins_t *x, uint8_t basehi, uint8_t baselo,
    int64_t imm, uint8_t indexing_mode)
{
	uint8_t ind = x->a64_num_opnds;
	uint8_t base = arm64_instr_extract_bits(x->a64_instr, basehi, baselo);
	arm64_opnd_type_t addr_mode;

	assert(ind < A64_MAX_OPNDS);

	assert(indexing_mode < 4);
	switch (indexing_mode) {
	case 0:
	case 2:
		addr_mode = A64_SIGNED_OFF;
		break;
	case 1:
		addr_mode = A64_POST_INDEX;
		break;
	case 3:
		addr_mode = A64_PRE_INDEX;
		break;
	}

	x->a64_opnds[ind].a64_type = addr_mode;
	x->a64_opnds[ind].a64_value.s_val = imm;
	x->a64_opnds[ind].a64_base = base;
	x->a64_num_opnds++;
}

static const char *arm64_adr_names[] = {
	"adr", "adrp"
};

static const char *arm64_addsub_names[] = {
	"add",	/* 00 */
	"adds",	/* 01 */
	"sub",	/* 10 */
	"subs",	/* 11 */
};

static const char *arm64_logical_imm_names[] = {
	"and",	/* 00 */
	"orr",	/* 01 */
	"eor",	/* 10 */
	"ands",	/* 11 */
};

static const char *arm64_mov_wide_imm_names[] = {
	"movn",	/* 00 */
	NULL,	/* 01 */
	"movz",	/* 10 */
	"movk",	/* 11 */
};

static const char *arm64_bitfield_imm_names[] = {
	"sbfm",	/* 00 */
	"bfm",	/* 01 */
	"ubfm",	/* 10 */
	NULL,	/* 11 */
};

static const char *arm64_extr_names[] = {
	"extr",	/* 00 */
	NULL,	/* 01 */
	NULL,	/* 10 */
	NULL,	/* 11 */
};

static int
arm64_dis_data_imm(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t op0 = arm64_instr_extract_bits(instr, 25, 23);
	boolean_t sf = arm64_instr_extract_bit(instr, 31);
	/* ADR{P} are always 64 bit, independent of sf */
	uint8_t operand_size = (sf || op0 < 2) ? A64_64BIT : A64_32BIT;

	/* Used as an opcode by most instructions. */
	uint8_t opc = arm64_instr_extract_bits(instr, 30, 29);

	/* Used by Logical, Bitfield and Extract instructions */
	boolean_t N = arm64_instr_extract_bit(instr, 22);

	/* Used by any sub functions that can return an error */
	int err;

	/* All Data immediate functions start with rd */
	arm64_extract_reg(x, 4, 0, operand_size, B_FALSE);

	switch (op0) {
	case 0:
	case 1: /* ADR{P} */
		x->a64_mnem = arm64_adr_names[sf];
		arm64_extract_adr_label(x);
		break;
	case 2:
	case 3: /* ADD{S} or SUB{S} */
		x->a64_mnem = arm64_addsub_names[opc];

		if (opc == 0 || opc == 2) {
			/* ADD and SUB use the SP in rd */
			x->a64_opnds[0].a64_type = A64_GP_REG_SP;
		}

		arm64_extract_reg(x, 9, 5, operand_size, B_TRUE);
		arm64_extract_imm(x, 21, 10);
		err = arm64_extract_shiftl_opnd(x, 23, 22, 12, 12);
		if (err != 0)
			return (err);
		break;
	case 4: /* Logic Functions */
		x->a64_mnem = arm64_logical_imm_names[opc];

		if (opc != 3) {
			/* ORR, EOR, AND all use the SP in rd (not ANDS) */
			x->a64_opnds[0].a64_type = A64_GP_REG_SP;
		}

		if (N && !sf) {
			/* Reserved value */
			return (-1);
		}

		arm64_extract_reg(x, 9, 5, operand_size, B_FALSE);

		/* Decodes the mess that is logical immediates in AARCH64 */
		arm64_extract_logical_imm(x, operand_size);
		break;
	case 5: /* Move wide */
		x->a64_mnem = arm64_mov_wide_imm_names[opc];
		if (x->a64_mnem == NULL)
			return (-1);

		arm64_extract_imm(x, 20, 5);

		/* 64 bit max shift is 48, 32 bit is 16. */
		err = arm64_extract_shiftl_opnd(x, 22, 21, 16, sf ? 48 : 16);
		if (err != 0)
			return (err);
		break;
	case 6: /* Bitfield instructions */
		x->a64_mnem = arm64_bitfield_imm_names[opc];
		if (x->a64_mnem == NULL)
			return (-1);

		if (N != sf) {
			/* Reserved value */
			return (-1);
		}

		arm64_extract_reg(x, 9, 5, operand_size, B_FALSE);
		arm64_extract_imm(x, 21, 16);
		arm64_extract_imm(x, 15, 10);
		break;
	case 7: /* Extract instructions */
		x->a64_mnem = arm64_extr_names[opc];
		if (x->a64_mnem == NULL)
			return (-1);

		N = arm64_instr_extract_bits(instr, 22, 22);
		if (N != sf) {
			/* Reserved value */
			return (-1);
		}

		arm64_extract_reg(x, 9, 5, operand_size, B_FALSE);
		arm64_extract_reg(x, 20, 16, operand_size, B_FALSE);
		arm64_extract_imm(x, 15, 10);
		break;
	}

	return (0);
}

static const char *arm64_load_reg_literal_names[] = {
	"ldr",		/* 00 */
	"ldr",		/* 01 */
	"ldrsw",	/* 10 */
	"prfm",		/* 11 */
};

/* Most Load/store instructions have rt at 4:0 */
static void
arm64_extract_ls_rt(arm64ins_t *x, arm64_opnd_size_t opnd_size)
{
	/* Rt is from 4:0 for load store */
	arm64_extract_reg(x, 4, 0, opnd_size, B_FALSE);
}

/*
 * Most Load/store instructions have a memory location operand based around
 * rn at 9:5.
 */
static void
arm64_extract_ls_rn_mem_loc(arm64ins_t *x, int64_t imm, uint8_t indexing_mode)
{
	arm64_extract_mem_loc(x, 9, 5, imm, indexing_mode);
}

static int
arm64_dis_load_reg_literal(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	boolean_t V = arm64_instr_extract_bit(instr, 26);
	uint8_t opc = arm64_instr_extract_bits(instr, 31, 30);
	arm64_opnd_size_t opnd_size = (opc > 0) ? A64_64BIT : A64_32BIT;

	if (V) {
		/* SIMD instructions not yet supported */
		return (-1);
	}

	x->a64_mnem = arm64_load_reg_literal_names[opc];

	arm64_extract_ls_rt(x, opnd_size);
	if (opc == 3) {
		/*
		 * PRFM is the exception to having an rt,
		 * which instead uses those 5 bits as prefetch options
		 */
		x->a64_opnds[0].a64_type = A64_PREFETCH_OPTIONS;
	}

	arm64_extract_label(x, 23, 5, 4);
	return (0);
}

static const char *arm64_ls_pair_noalloc_names[] = {
	"stnp", "ldnp",
};

static const char *arm64_ls_pair_names[] = {
	"stp", "ldp",
};

static const char *arm64_ls_pair_signed_names[] = {
	NULL, "ldpsw",
};

static int
arm64_dis_ls_pair(arm64ins_t *x, uint8_t indexing_op)
{
	/*
	 * The main difference in these instructions is how they display
	 * their memory addresses (aka the operand types)
	 */
	uint32_t instr = x->a64_instr;
	int64_t imm7 = arm64_instr_extract_signed_num(instr, 21, 15);
	boolean_t V = arm64_instr_extract_bit(instr, 26);
	uint8_t L = arm64_instr_extract_bits(instr, 22, 22);
	uint8_t opc = arm64_instr_extract_bits(instr, 31, 30);
	arm64_opnd_size_t opnd_size = (opc > 0) ? A64_64BIT : A64_32BIT;
	/* 32 bit variants and LDPSW multiply by 4, others by 8 */
	uint8_t imm_multiplier = (opc > 1) ? 8 : 4;
	int64_t addr_offset = imm7 * imm_multiplier;
	arm64_opnd_type_t op3_type;

	if (V) {
		/* SIMD/FP instructions -- ignore for now */
		return (-1);
	}

	if (opc == 3) {
		/* Reserved value */
		return (-1);
	}

	/* Determine mnem based on it being no alloc, signed or regular */
	if (indexing_op == 0) {
		x->a64_mnem = arm64_ls_pair_noalloc_names[L];
	} else if (opc == 1) {
		x->a64_mnem = arm64_ls_pair_signed_names[L];
	} else {
		x->a64_mnem = arm64_ls_pair_names[L];
	}
	if (x->a64_mnem == NULL)
		return (-1);

	/* Extract rt */
	arm64_extract_ls_rt(x, opnd_size);
	/* Extract rt2 */
	arm64_extract_reg(x, 14, 10, opnd_size, B_FALSE);
	/* Extract memory address operand */
	arm64_extract_ls_rn_mem_loc(x, addr_offset, indexing_op);

	return (0);
}

/* Indexed by [size][opc] */
static const char *arm64_ls_register_unscaled_names[][4] = {
	{ "sturb", "ldurb", "ldursb", "ldursb"},
	{ "sturh", "ldurh", "ldursh", "ldursh" },
	{ "stur", "ldur", "ldursw", NULL },
	{ "stur", "ldur", "prfum", NULL },
};

/* Indexed by [size][opc] */
static const char *arm64_ls_register_base_names[][4] = {
	{ "strb", "ldrb", "ldrsb", "ldrsb"},
	{ "strh", "ldrh", "ldrsh", "ldrsh" },
	{ "str", "ldr", "ldrsw", NULL },
	{ "str", "ldr", "prfm", NULL },
	/*
	 * This is used by pre indexed, post indexed, and unsigned immediate
	 * variants. However, only unsigned immediate uses "prfm", so code
	 * should check for that case when using this array.
	 */
};

/* Indexed by [size][opc] */
static const char *arm64_ls_register_unpriv_names[][4] = {
	{ "sttrb", "ldtrb", "ldtrsb", "ldtrsb"},
	{ "sttrh", "ldtrh", "ldtrsh", "ldtrsh" },
	{ "sttr", "ldtr", "ldtrsw", NULL },
	{ "sttr", "ldtr", NULL, NULL },
};

static int
arm64_dis_ls_register_signed_imm(arm64ins_t *x, uint8_t indexing_op)
{
	uint32_t instr = x->a64_instr;

	uint8_t size = arm64_instr_extract_bits(instr, 31, 30);
	boolean_t V = arm64_instr_extract_bit(instr, 26);
	uint8_t opc = arm64_instr_extract_bits(instr, 23, 22);
	arm64_opnd_size_t rt_size = (size == 3 || opc == 2) ? A64_64BIT
	    : A64_32BIT;
	int64_t addr_offset = arm64_instr_extract_signed_num(instr, 20, 12);

	if (V) {
		/* SIMD/FP instructions -- ignore for now */
		return (-1);
	}

	assert(indexing_op < 4);
	switch (indexing_op) {
	case 0:
		x->a64_mnem = arm64_ls_register_unscaled_names[size][opc];
		break;
	case 1:
	case 3:
		if (size == 3 && opc == 2) {
			/*
			 * This array has "prfm" here despite being invalid
			 * for these instructions
			 */
			return (-1);
		}
		x->a64_mnem = arm64_ls_register_base_names[size][opc];
		break;
	case 2:
		x->a64_mnem = arm64_ls_register_unpriv_names[size][opc];
		break;
	}
	if (x->a64_mnem == NULL) {
		return (-1);
	}

	/* All start with RT, except for PRFM but uses the same bits */
	arm64_extract_reg(x, 4, 0, rt_size, B_FALSE);
	if (opc == 2 && size == 3) {
		x->a64_opnds[0].a64_type = A64_PREFETCH_OPTIONS;
	}

	/* Then memory loc, determined by rn, offset and index mode */
	arm64_extract_ls_rn_mem_loc(x, addr_offset, indexing_op);

	return (0);
}

static int
arm64_dis_ls_register_unsigned_imm(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	uint8_t size = arm64_instr_extract_bits(instr, 31, 30);
	boolean_t V = arm64_instr_extract_bit(instr, 26);
	uint8_t opc = arm64_instr_extract_bits(instr, 23, 22);
	arm64_opnd_size_t rt_size = (size == 3 || opc == 2) ? A64_64BIT
	    : A64_32BIT;
	/* Immediate is shifted by size to determine positive offset */
	uint64_t addr_offset = arm64_instr_extract_bits(instr, 21, 10) << size;

	if (V) {
		/* SIMD/FP instructions -- ignore for now */
		return (-1);
	}

	x->a64_mnem = arm64_ls_register_base_names[size][opc];
	if (x->a64_mnem == NULL) {
		return (-1);
	}

	/* All start with RT, except for PRFM but uses the same bits */
	arm64_extract_reg(x, 4, 0, rt_size, B_FALSE);
	if (opc == 2 && size == 3) {
		x->a64_opnds[0].a64_type = A64_PREFETCH_OPTIONS;
	}

	/*
	 * Fine to cast addr_offset to a signed value since it is at most
	 * 15 bits, which fits well within positive values of int64_t.
	 * Assert statement ensures this.
	 */
	assert(flsll(addr_offset) <= 16);
	arm64_extract_ls_rn_mem_loc(x, (int64_t)addr_offset, 0);

	return (0);
}

static int
arm64_dis_ls_shifted_extended_reg(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	uint8_t size = arm64_instr_extract_bits(instr, 31, 30);
	boolean_t V = arm64_instr_extract_bit(instr, 26);
	uint8_t opc = arm64_instr_extract_bits(instr, 23, 22);
	arm64_opnd_size_t rt_size = (size == 3 || opc == 2) ? A64_64BIT
	    : A64_32BIT;
	uint8_t option = arm64_instr_extract_bits(instr, 15, 13);
	boolean_t S = arm64_instr_extract_bit(instr, 12);
	arm64_opnd_t *mem_reg_opnd;
	arm64_mem_reg_t *mem_reg;

	if (V) {
		/* SIMD/FP instructions -- ignore for now */
		return (-1);
	}

	if (option != 2 && option != 3 && option != 6 && option != 7) {
		/* Valid extension/shift options */
		return (-1);
	}

	/* Uses same names as imm indexed */
	x->a64_mnem = arm64_ls_register_base_names[size][opc];
	if (x->a64_mnem == NULL) {
		return (-1);
	}

	/* All start with RT, except for PRFM but uses the same bits */
	arm64_extract_reg(x, 4, 0, rt_size, B_FALSE);
	if (opc == 2 && size == 3) {
		x->a64_opnds[0].a64_type = A64_PREFETCH_OPTIONS;
	}

	/*
	 * Extended/shifted reg addresses use the following data:
	 *
	 * A base register, stored in opnd.a64_base (like other memory modes,
	 *	always 64 bit, and can be SP)
	 * A register to extend - mem_reg.a64_reg
	 * That register's size - mem_reg.a64_regsize
	 * The extension/shift operation - mem_reg.a64_ext_op
	 *	(optionally displayed)
	 * The extension/shift's immediate - mem_reg.a64_ext_imm
	 *	(optionally displayed)
	 * Thus giving the form:
	 * [<Xn|Sp>, (<Wm>|<Xm>){, <operation> {<amount>}}]
	 */
	mem_reg_opnd = &x->a64_opnds[x->a64_num_opnds];
	mem_reg = &mem_reg_opnd->a64_value.mem_reg;

	mem_reg_opnd->a64_type = A64_REG_INDEX;
	mem_reg_opnd->a64_base = arm64_instr_extract_bits(instr, 9, 5);
	x->a64_num_opnds++;

	mem_reg->a64_reg = arm64_instr_extract_bits(instr, 20, 16);
	mem_reg->a64_regsize = (option & 0x1) ? A64_64BIT : A64_32BIT;
	mem_reg->a64_ext_op = option;
	/*
	 * Display extension/shift op when there is an immediate, or if the
	 * operation is not lsl (== 0x3)
	 */
	mem_reg->a64_display_op = (S || option != 0x3);
	/* Display immediate when displaying an op and S is true */
	mem_reg->a64_display_imm = (mem_reg->a64_display_op && S);

	switch (size) {
	case 0:
		/* Immediate is always 0 for this size */
		mem_reg->a64_ext_imm = 0;
		break;
	case 1:
		/* Immediate is 0 or 1 for this size */
		mem_reg->a64_ext_imm = S;
		break;
	case 2:
		/* Immediate is 0 or 2 for this size */
		mem_reg->a64_ext_imm = S ? 2 : 0;
		break;
	case 3:
		/* Immediate is 0 or 3 for this size */
		mem_reg->a64_ext_imm = S ? 3 : 0;
		break;
	}

	return (0);
}

static const char *arm64_ls_exclusive_byte_names[16] = {
	[0x0] = "stxrb",
	[0x1] = "stlxrb",
	[0x4] = "ldxrb",
	[0x5] = "ldaxrb",
	[0x9] = "stlrb",
	[0xd] = "ldarb",
};

static const char *arm64_ls_exclusive_halfword_names[16] = {
	[0x0] = "stxrh",
	[0x1] = "stlxrh",
	[0x4] = "ldxrh",
	[0x5] = "ldaxrh",
	[0x9] = "stlrh",
	[0xd] = "ldarh",
};

static const char *arm64_ls_exclusive_word_dword_names[16] = {
	[0x0] = "stxr",
	[0x1] = "stlxr",
	[0x2] = "stxp",
	[0x3] = "stlxp",
	[0x4] = "ldxr",
	[0x5] = "ldaxr",
	[0x6] = "ldxp",
	[0x7] = "ldaxp",
	[0x9] = "stlr",
	[0xd] = "ldar",
};

static int
arm64_dis_ls_exclusive(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	uint8_t size = arm64_instr_extract_bits(instr, 31, 30);
	uint8_t name_ind = arm64_instr_extract_bits(instr, 23, 21);
	boolean_t o2 = arm64_instr_extract_bits(instr, 23, 23);
	boolean_t L = arm64_instr_extract_bits(instr, 22, 22);
	boolean_t o1 = arm64_instr_extract_bits(instr, 21, 21);
	boolean_t o0 = arm64_instr_extract_bits(instr, 15, 15);
	arm64_opnd_size_t rt_size = (size == 3) ? A64_64BIT : A64_32BIT;

	/*
	 * There's a lot of different opcodes here, so we determine the mnem
	 * array by 'size' and index into those with o2:L:o1:o0
	 */
	name_ind = (name_ind << 1) + o0;
	switch (size) {
	case 0:
		x->a64_mnem = arm64_ls_exclusive_byte_names[name_ind];
		break;
	case 1:
		x->a64_mnem = arm64_ls_exclusive_halfword_names[name_ind];
		break;
	default:
		x->a64_mnem = arm64_ls_exclusive_word_dword_names[name_ind];
		break;
	}
	if (x->a64_mnem == NULL) {
		return (-1);
	}

	/* Instructions that aren't Load or o2 have Ws as first operand */
	if (!o2 && !L) {
		arm64_extract_reg(x, 20, 16, A64_32BIT, B_FALSE);
	}

	/* Next, all instructions have rt */
	arm64_extract_ls_rt(x, rt_size);

	/* Instructions with o1 set have rt2 */
	if (o1) {
		arm64_extract_reg(x, 14, 10, rt_size, B_FALSE);
	}

	/* Last operand is always [<Xn|SP> #0] */
	arm64_extract_ls_rn_mem_loc(x, 0, 0);

	return (0);
}

static int
arm64_dis_load_store(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	/* First step of decoding load/store involves all these opcodes */
	uint8_t op1 = arm64_instr_extract_bits(instr, 29, 28);
	boolean_t op2 = arm64_instr_extract_bit(instr, 26);
	uint8_t op3 = arm64_instr_extract_bits(instr, 24, 23);
	uint8_t op4 = arm64_instr_extract_bits(instr, 21, 16);
	uint8_t op5 = arm64_instr_extract_bits(instr, 11, 10);

	int ret = -1;
	switch (op1) {
	case 0:
		if (op2) {
			/* Unallocated or SIMD load/store */
		} else if (op3 < 2) {
			ret = arm64_dis_ls_exclusive(x);
		}
		break;
	case 1:
		if (op3 < 2) {
			ret = arm64_dis_load_reg_literal(x);
		}
		break;
	case 2:
		ret = arm64_dis_ls_pair(x, op3);
		break;
	case 3:
		if (op3 >= 2) {
			ret = arm64_dis_ls_register_unsigned_imm(x);
		} else if (op4 < 32) {
			ret = arm64_dis_ls_register_signed_imm(x, op5);
		} else if (op5 == 2) {
			ret = arm64_dis_ls_shifted_extended_reg(x);
		}
		/*
		 * Rest of instructions here are atomic memory operations
		 * which are arm v8.1, so not yet supported or L/S register
		 * - PAC which is arm v8.3 and not yet supported
		 */
		break;
	}

	return (ret);
}

static const char *arm64_cond_branch_names[] = {
	"b.eq",	/* 0000 */
	"b.ne",	/* 0001 */
	"b.cs",	/* 0010 aka "hs" */
	"b.cc",	/* 0011 aka "lo" */
	"b.mi",	/* 0100 */
	"b.pl",	/* 0101 */
	"b.vs",	/* 0110 */
	"b.vc",	/* 0111 */
	"b.hi",	/* 1000 */
	"b.ls",	/* 1001 */
	"b.ge",	/* 1010 */
	"b.lt",	/* 1011 */
	"b.gt",	/* 1100 */
	"b.le",	/* 1101 */
	"b.al",	/* 1110 */
	"b.nv",	/* 1111 */
};

static int
arm64_dis_cond_branch(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	boolean_t o0 = arm64_instr_extract_bit(instr, 4);
	boolean_t o1 = arm64_instr_extract_bit(instr, 24);
	uint8_t cond_code = arm64_instr_extract_bits(instr, 3, 0);

	if (o1 || o0) {
		/* Unallocated insruction */
		return (-1);
	}

	x->a64_mnem = arm64_cond_branch_names[cond_code];
	arm64_extract_label(x, 23, 5, 4);

	return (0);
}

static const char *arm64_uncond_branch_reg_names[] = {
	"br",
	"blr",
	"ret",
	NULL,
	"eret",
	"drps",
};

static int
arm64_dis_uncond_branch_reg(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t opc = arm64_instr_extract_bits(instr, 24, 21);
	uint8_t op2 = arm64_instr_extract_bits(instr, 20, 16);
	uint8_t op3 = arm64_instr_extract_bits(instr, 15, 10);
	uint8_t rn = arm64_instr_extract_bits(instr, 9, 5);
	uint8_t op4 = arm64_instr_extract_bits(instr, 4, 0);

	if (op4 != 0) {
		/* Unallocated or arm8.3 */
		return (-1);
	}
	if (op3 != 0) {
		/* Unallocated or arm8.3 */
		return (-1);
	}
	if (op2 != 31) {
		/* Unallocated */
		return (-1);
	}
	if (opc > 7) {
		/* Unallocated or arm8.3 */
		return (-1);
	}

	x->a64_mnem = arm64_uncond_branch_reg_names[opc];

	/*
	 * Only operand is rn for BR, BLR and RET. Exception is when rn == 30,
	 * we don't actually display it for RET, since this is default.
	 */
	if (opc <= 1 || (opc == 2 && rn != 30)) {
		arm64_extract_reg(x, 9, 5, 64, B_FALSE);
	} else if (opc > 2 && rn != 31) {
		/* ERET/DRPS have no opnds; rn must be 31 */
		return (-1);
	}

	return (0);
}

static const char *arm64_uncond_branch_imm_names[] = {
	"b",
	"bl"
};

static int
arm64_dis_uncond_branch_imm(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t op = arm64_instr_extract_bits(instr, 31, 31);

	x->a64_mnem = arm64_uncond_branch_imm_names[op];

	arm64_extract_label(x, 25, 0, 4);

	return (0);
}

static const char *arm64_compare_branch_names[] = {
	"cbz",
	"cbnz"
};

static int
arm64_dis_compare_branch(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	boolean_t sf = arm64_instr_extract_bit(instr, 31);
	uint8_t op = arm64_instr_extract_bits(instr, 24, 24);

	x->a64_mnem = arm64_compare_branch_names[op];

	arm64_extract_reg(x, 4, 0, sf ? A64_64BIT : A64_32BIT, B_FALSE);
	arm64_extract_label(x, 23, 5, 4);

	return (0);
}

static const char *arm64_test_branch_names[] = {
	"tbz",
	"tbnz"
};

static int
arm64_dis_test_branch(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	uint8_t b5 = arm64_instr_extract_bits(instr, 31, 31);
	uint8_t op = arm64_instr_extract_bits(instr, 24, 24);
	uint8_t b40 = arm64_instr_extract_bits(instr, 23, 19);
	arm64_opnd_size_t opnd_size = (b5 == 1) ? A64_64BIT : A64_32BIT;

	x->a64_mnem = arm64_test_branch_names[op];

	/* rt */
	arm64_extract_reg(x, 4, 0, opnd_size, B_FALSE);

	/* Opnd2 is the bit number to test, encoded by {b5:b40} */
	x->a64_opnds[1].a64_type = A64_IMMEDIATE;
	x->a64_opnds[1].a64_value.u_val = (b5 << 5) + b40;
	x->a64_num_opnds++;

	/* Label to branch to == imm * 4 + pc */
	arm64_extract_label(x, 18, 5, 4);

	return (0);
}

static const char *arm64_exception_gen_names[][4] = {
	{ NULL, "svc", "hvc", "smc"},		/* opc == 000, indexed by LL */
	{ "brk", NULL, NULL, NULL },		/* opc == 001 */
	{ "hlt", NULL, NULL, NULL },		/* opc == 010 */
	{ NULL, NULL, NULL, NULL },		/* opc == 011 */
	{ NULL, NULL, NULL, NULL },		/* opc == 100 */
	{ NULL, "dcps1", "dcps2", "dcps3" },	/* opc == 101 */
	{ NULL, NULL, NULL, NULL },		/* opc == 110 */
	{ NULL, NULL, NULL, NULL },		/* opc == 111 */
};

static int
arm64_dis_exception_gen(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t opc = arm64_instr_extract_bits(instr, 23, 21);
	uint8_t op2 = arm64_instr_extract_bits(instr, 4, 2);
	uint8_t LL = arm64_instr_extract_bits(instr, 1, 0);

	if (op2 > 0) {
		return (-1);
	}

	x->a64_mnem = arm64_exception_gen_names[opc][LL];
	if (x->a64_mnem == NULL) {
		return (-1);
	}

	/* All have one operand, imm16 between 20, 5 */
	arm64_extract_imm(x, 20, 5);

	return (0);
}

static const char *arm64_hint_names_0[] = {
	"nop",
	"yield",
	"wfe",
	"wfi",
	"sev",
	"sevl",
	NULL,
	NULL,
};

static const char *arm64_hint_names_2[8] = {
	[0x0] = "esb",		/* 000 */
	[0x1] = "psb csync",	/* 001 */
};

static const char *default_hint_name = "hint";

static int
arm64_dis_hint(arm64ins_t *x, uint8_t CRm, uint8_t op2)
{
	if (CRm == 0) {
		x->a64_mnem = arm64_hint_names_0[op2];
	} else if (CRm == 2) {
		x->a64_mnem = arm64_hint_names_2[op2];
	}

	/* If the hint type is not allocated, print the immediate */
	if (x->a64_mnem == NULL) {
		x->a64_mnem = default_hint_name;
		arm64_extract_imm(x, 11, 5);
	}

	return (0);
}

static const char *arm64_system_crn3_names[] = {
	NULL, NULL, "clrex", NULL,
	"dsb", "dmb", "isb", NULL,
};

static int
arm64_dis_system_crn3(arm64ins_t *x, uint8_t CRm, uint8_t op2)
{
	x->a64_mnem = arm64_system_crn3_names[op2];
	if (x->a64_mnem == NULL)
		return (-1);

	if ((op2 == 2 || op2 == 6) && CRm == 15) {
		/* CLREX and ISB only needs the mnem in this case */
		return (0);
	}

	x->a64_opnds[0].a64_type = (op2 == 2 || op2 == 6) ? A64_IMMEDIATE
	    : A64_BARRIER_OP;
	x->a64_opnds[0].a64_value.u_val = CRm;
	x->a64_num_opnds++;

	return (0);
}

static const char *arm64_system_sys_names[] = {
	"sys", "sysl"
};

static int
arm64_dis_system_sys(arm64ins_t *x, boolean_t L)
{
	x->a64_mnem = arm64_system_sys_names[L];
	uint8_t rt = arm64_instr_extract_bits(x->a64_instr, 4, 0);

	if (L) {
		/* Xt for SYSL */
		arm64_extract_reg(x, 4, 0, 64, B_FALSE);
	}

	/* #op1 */
	arm64_extract_imm(x, 18, 16);

	/* Cn */
	arm64_extract_unnamed_sys_reg(x, 15, 12);

	/* Cm */
	arm64_extract_unnamed_sys_reg(x, 11, 8);

	/* #op2 */
	arm64_extract_imm(x, 7, 5);

	if (!L && rt != 31) {
		/* Xt for SYS */
		arm64_extract_reg(x, 4, 0, 64, B_FALSE);
	}

	return (0);
}

static const char *arm64_system_move_names[] = {
	"msr", "mrs"
};

static int
arm64_dis_system_move(arm64ins_t *x, boolean_t L)
{
	x->a64_mnem = arm64_system_move_names[L];

	if (L) {
		arm64_extract_reg(x, 4, 0, 64, B_FALSE);
	}
	arm64_extract_named_sys_reg(x);
	if (!L) {
		arm64_extract_reg(x, 4, 0, 64, B_FALSE);
	}

	return (0);
}

static int
arm64_dis_system_move_imm(arm64ins_t *x, uint8_t op1, uint8_t op2, uint8_t CRm)
{
	uint8_t pstate_val = (op1 << 3) | op2;
	assert(op1 < 8 && op2 < 8); /* Both should be only 3 bits */
	assert(CRm < 16);

	/*
	 * Mnem is MSR = Move (imm) to Special Register, which is
	 * arm64_system_move_names[0]
	 */
	x->a64_mnem = arm64_system_move_names[0];

	/*
	 * First opnd is a psatefield, encoded in op1:op2
	 * SPSel	= 000:101 == 0x5
	 * DAIFSet	= 011:110 == 0x1e
	 * DAIFClr	= 011:111 == 0x1f
	 * Other values are reserved, or arm v8.2/8.1
	 */
	if (pstate_val != 0x5 && pstate_val != 0x1e && pstate_val != 0x1f) {
		return (-1);
	}
	x->a64_opnds[0].a64_type = A64_PSTATEFIELD;
	x->a64_opnds[0].a64_value.u_val = pstate_val;
	x->a64_num_opnds++;

	/* Next operand is an immediate, of value CRm */
	x->a64_opnds[1].a64_type = A64_IMMEDIATE;
	x->a64_opnds[1].a64_value.u_val = CRm;
	x->a64_num_opnds++;

	return (0);
}

static int
arm64_dis_system(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	boolean_t L = arm64_instr_extract_bit(instr, 21);
	uint8_t op0 = arm64_instr_extract_bits(instr, 20, 19);
	uint8_t op1 = arm64_instr_extract_bits(instr, 18, 16);
	uint8_t CRn = arm64_instr_extract_bits(instr, 15, 12);
	uint8_t CRm = arm64_instr_extract_bits(instr, 11, 8);
	uint8_t op2 = arm64_instr_extract_bits(instr, 7, 5);

	if (!L && op0 == 0 && CRn == 4) {
		return (arm64_dis_system_move_imm(x, op1, op2, CRm));
	}

	if (!L && op0 == 0 && op1 == 3) {
		if (CRn == 2) {
			return (arm64_dis_hint(x, CRm, op2));
		} else if (CRn == 3) {
			return (arm64_dis_system_crn3(x, CRm, op2));
		} else {
			return (-1);
		}
	}

	if (op0 == 1) {
		return (arm64_dis_system_sys(x, L));
	} else if (op0 > 1) {
		return (arm64_dis_system_move(x, L));
	}

	return (-1);
}

static int
arm64_dis_misc(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t op0 = arm64_instr_extract_bits(instr, 31, 29);
	uint8_t op1 = arm64_instr_extract_bits(instr, 25, 22);
	int ret = -1;

	switch (op0) {
	case 2:
		if (op1 < 8) {
			ret = arm64_dis_cond_branch(x);
		}
		break;
	case 6:
		if (op1 >= 8) {
			ret = arm64_dis_uncond_branch_reg(x);
		} else if (op1 == 4) {
			ret = arm64_dis_system(x);
		} else if (op1 < 4) {
			ret = arm64_dis_exception_gen(x);
		}
		break;
	case 0:
	case 4:
		ret = arm64_dis_uncond_branch_imm(x);
		break;
	case 1:
	case 5:
		if (op1 < 8) {
			ret = arm64_dis_compare_branch(x);
		} else {
			ret = arm64_dis_test_branch(x);
		}
		break;
	/* All other unallocated */
	}

	return (ret);
}

static const char *arm64_data_2src_names[16] = {
	[0x2] = "udiv", /* 0010 */
	[0x3] = "sdiv", /* 0011 */
	[0x8] = "lsl",	/* 1000 */
	[0x9] = "lsr",	/* 1001 */
	[0xa] = "asr",	/* 1010 */
	[0xb] = "ror",	/* 1011 */
};

static int
arm64_dis_data_2src(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	boolean_t sf = arm64_instr_extract_bit(instr, 31);
	boolean_t S = arm64_instr_extract_bit(instr, 29);
	uint8_t opcode = arm64_instr_extract_bits(instr, 15, 10);
	arm64_opnd_size_t bitsize = sf ? A64_64BIT : A64_32BIT;

	if (S) {
		/* Unallocated */
		return (-1);
	}
	if (opcode > 16) {
		/* Unallocated or Unsupported */
		return (-1);
	}

	x->a64_mnem = arm64_data_2src_names[opcode];
	if (x->a64_mnem == NULL)
		return (-1);

	arm64_extract_reg(x, 4, 0, bitsize, B_FALSE);
	arm64_extract_reg(x, 9, 5, bitsize, B_FALSE);
	arm64_extract_reg(x, 20, 16, bitsize, B_FALSE);

	return (0);
}

static const char *arm64_data_1src_names_32[] = {
	"rbit",
	"rev16",
	"rev",
	NULL,
	"clz",
	"cls",
};

static const char *arm64_data_1src_names_64[] = {
	"rbit",
	"rev16",
	"rev32",
	"rev",
	"clz",
	"cls",
};


static int
arm64_dis_data_1src(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	boolean_t sf = arm64_instr_extract_bit(instr, 31);
	boolean_t S = arm64_instr_extract_bit(instr, 29);
	uint8_t opcode = arm64_instr_extract_bits(instr, 15, 10);
	uint8_t opcode2 = arm64_instr_extract_bits(instr, 20, 16);
	arm64_opnd_size_t bitsize;

	if (opcode >= 6 || opcode2 > 0 || S) {
		return (-1);
	}

	/* Slightly different names per bitsize */
	if (sf) {
		bitsize = A64_64BIT;
		x->a64_mnem = arm64_data_1src_names_64[opcode];
	} else {
		bitsize = A64_32BIT;
		x->a64_mnem = arm64_data_1src_names_32[opcode];
	}
	if (x->a64_mnem == NULL) {
		return (-1);
	}

	/* Then add rd then rn */
	arm64_extract_reg(x, 4, 0, bitsize, B_FALSE);
	arm64_extract_reg(x, 9, 5, bitsize, B_FALSE);

	return (0);
}

static void
arm64_extract_data_rd_rn_rm(arm64ins_t *x)
{
	boolean_t sf = arm64_instr_extract_bit(x->a64_instr, 31);
	arm64_opnd_size_t bitsize = sf ? A64_64BIT : A64_32BIT;

	arm64_extract_reg(x, 4, 0, bitsize, B_FALSE);
	arm64_extract_reg(x, 9, 5, bitsize, B_FALSE);
	arm64_extract_reg(x, 20, 16, bitsize, B_FALSE);
}

static void
arm64_extract_shifted_reg_operands(arm64ins_t *x)
{
	arm64_extract_data_rd_rn_rm(x);
	arm64_extract_shifted_reg_shift(x);
}

static void
arm64_extract_extended_reg_operands(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	boolean_t sf = arm64_instr_extract_bit(instr, 31);
	uint8_t option = arm64_instr_extract_bits(instr, 15, 13);
	uint8_t imm3 = arm64_instr_extract_bits(instr, 12, 10);
	arm64_opnd_size_t bitsize = sf ? A64_64BIT : A64_32BIT;
	arm64_opnd_size_t rm_bitsize = bitsize;

	/* rd and rn are similar to shifted reg, but can be SP */
	arm64_extract_reg(x, 4, 0, bitsize, B_TRUE);
	arm64_extract_reg(x, 9, 5, bitsize, B_TRUE);

	/* rm is done differently, based on option and can't be SP */
	if ((option & 0x3) != 0x3) {
		rm_bitsize = A64_32BIT;
	}

	arm64_extract_reg(x, 20, 16, rm_bitsize, B_FALSE);

	x->a64_opnds[3].a64_type = A64_EXTENSION;
	x->a64_opnds[3].a64_value.u_val = option;
	x->a64_opnds[3].a64_base = imm3;
	x->a64_opnds[3].a64_bitsize = bitsize;
	x->a64_num_opnds++;
}

static const char *arm64_logic_shifted_reg_names[] = {
	"and",
	"bic",
	"orr",
	"orn",
	"eor",
	"eon",
	"ands",
	"bics",
};

static int
arm64_dis_logic_shifted_reg(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t opc = arm64_instr_extract_bits(instr, 30, 29);
	uint8_t n = arm64_instr_extract_bits(instr, 21, 21);

	x->a64_mnem = arm64_logic_shifted_reg_names[(opc << 1) + n];
	arm64_extract_shifted_reg_operands(x);

	return (0);
}

static int
arm64_dis_addsub_shifted_extended_reg(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t ops = arm64_instr_extract_bits(instr, 30, 29);
	boolean_t is_extended = arm64_instr_extract_bit(instr, 21);

	x->a64_mnem = arm64_addsub_names[ops];

	if (is_extended) {
		arm64_extract_extended_reg_operands(x);
	} else {
		arm64_extract_shifted_reg_operands(x);
	}

	return (0);
}

static const char *arm64_addsub_carry_names[] = {
	"adc",	/* 00 */
	"adcs",	/* 01 */
	"sbc",	/* 10 */
	"sbcs",	/* 11 */
};

static int
arm64_dis_addsub_carry(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t ops = arm64_instr_extract_bits(instr, 30, 29);
	uint8_t opcode2 = arm64_instr_extract_bits(instr, 15, 10);
	if (opcode2 > 0) {
		return (-1);
	}

	x->a64_mnem = arm64_addsub_carry_names[ops];

	arm64_extract_data_rd_rn_rm(x);
	return (0);
}

static const char *arm64_cond_compare_names[] = {
	"ccmn", "ccmp"
};

static int
arm64_dis_cond_compare(arm64ins_t *x, boolean_t use_imm)
{
	uint32_t instr = x->a64_instr;
	boolean_t sf = arm64_instr_extract_bit(instr, 31);
	uint8_t op = arm64_instr_extract_bits(instr, 30, 30);
	boolean_t S = arm64_instr_extract_bit(instr, 29);
	boolean_t o2 = arm64_instr_extract_bit(instr, 10);
	boolean_t o3 = arm64_instr_extract_bit(instr, 4);
	arm64_opnd_size_t bitsize = sf ? A64_64BIT : A64_32BIT;

	if (o3 || o2 || !S) {
		/* Unallocated values */
		return (-1);
	}
	x->a64_mnem = arm64_cond_compare_names[op];

	arm64_extract_reg(x, 9, 5, bitsize, B_FALSE);

	/* Next operand is a register or immediate */
	if (use_imm) {
		arm64_extract_imm(x, 20, 16);
	} else {
		arm64_extract_reg(x, 20, 16, bitsize, B_FALSE);
	}

	arm64_extract_flags_state(x, 15, 12);
	arm64_extract_condition(x, 3, 0);

	return (0);
}

static const char *arm64_cond_sel_names[] = {
	"csel", "csinc", "csinv", "csneg",
};

static int
arm64_dis_cond_select(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;
	uint8_t op = arm64_instr_extract_bits(instr, 30, 30);
	boolean_t S = arm64_instr_extract_bit(instr, 29);
	uint8_t op2 = arm64_instr_extract_bits(instr, 11, 10);

	if (S || op2 > 1) {
		/* Unallocated */
		return (-1);
	}

	x->a64_mnem = arm64_cond_sel_names[(op << 1) + op2];

	arm64_extract_data_rd_rn_rm(x);
	arm64_extract_condition(x, 15, 12);

	return (0);
}

static const char *arm64_data_3src_names[][2] = {
	{ "madd", "msub", },		/* op31 == 000, indexed by o0 */
	{ "smaddl", "smsubl", },	/* op31 == 001 */
	{ "smulh", NULL, },		/* op31 == 010 */
	{ NULL, NULL, },		/* op31 == 011 */
	{ NULL, NULL, },		/* op31 == 100 */
	{ "umaddl", "umsubl", },	/* op31 == 101 */
	{ "umulh", NULL, },		/* op31 == 110 */
	{ NULL, NULL, },		/* op31 == 111 */
};

static int
arm64_dis_data_3src(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	boolean_t sf = arm64_instr_extract_bit(instr, 31);
	uint8_t op54 = arm64_instr_extract_bits(instr, 30, 29);
	uint8_t op31 = arm64_instr_extract_bits(instr, 23, 21);
	uint8_t o0 = arm64_instr_extract_bits(instr, 15, 15);
	arm64_opnd_size_t opnd_size = sf ? A64_64BIT : A64_32BIT;
	uint8_t rn_rm_opnd_size = (op31 == 1 || op31 == 5) ? A64_32BIT :
	    opnd_size;

	if (op54 > 0 || (!sf && op31 > 0)) {
		return (-1);
	}

	x->a64_mnem = arm64_data_3src_names[op31][o0];
	if (x->a64_mnem == NULL) {
		return (-1);
	}

	/* All have rd, according to opnd_size */
	arm64_extract_reg(x, 4, 0, opnd_size, B_FALSE);

	/* SMADDL/SMSUBL and UMADDL/UMSUBL both have 32 bit operands here */
	arm64_extract_reg(x, 9, 5, rn_rm_opnd_size, B_FALSE);
	arm64_extract_reg(x, 20, 16, rn_rm_opnd_size, B_FALSE);

	/* SMULH/UMULH don't have a 4th operand */
	if (op31 != 2 && op31 != 6) {
		arm64_extract_reg(x, 14, 10, opnd_size, B_FALSE);
	}

	return (0);
}

static int
arm64_dis_data_reg(arm64ins_t *x)
{
	uint32_t instr = x->a64_instr;

	uint8_t op0 = arm64_instr_extract_bits(instr, 30, 30);
	boolean_t op1 = arm64_instr_extract_bit(instr, 28);
	uint8_t op2 = arm64_instr_extract_bits(instr, 24, 21);
	boolean_t op3 = arm64_instr_extract_bit(instr, 11);

	int ret;

	if (op1) {
		switch (op2) {
		case 0:
			ret = arm64_dis_addsub_carry(x);
			break;
		case 2:
			ret = arm64_dis_cond_compare(x, op3);
			break;
		case 4:
			ret = arm64_dis_cond_select(x);
			break;
		case 6:
			if (op0) {
				ret = arm64_dis_data_1src(x);
			} else {
				ret = arm64_dis_data_2src(x);
			}
			break;
		case 1:
		case 3:
		case 5:
			/* Unallocated */
			ret = -1;
			break;
		default:
			ret = arm64_dis_data_3src(x);
			break;
		}
	} else {
		if (op2 < 8) {
			ret = arm64_dis_logic_shifted_reg(x);
		} else {
			ret = arm64_dis_addsub_shifted_extended_reg(x);
		}
	}

	return (ret);
}

/* ARGSUSED */
static int
arm64_dis_data_adv(arm64ins_t *x)
{
	/* TODO: Advanced SIMD/FP Operations */
	return (-1);
}

int
arm64_decode(arm64ins_t *x)
{
	int ret = -1;
	uint8_t grp_code = (x->a64_instr & A64_GC_MASK) >> A64_GC_SHIFT;

	if ((grp_code & A64_GC_DATA_IMM_MASK) == A64_GC_DATA_IMM) {
		ret = arm64_dis_data_imm(x);
	} else if ((grp_code & A64_GC_LOAD_STORE_MASK) == A64_GC_LOAD_STORE) {
		ret = arm64_dis_load_store(x);
	} else if ((grp_code & A64_GC_MISC_MASK) == A64_GC_MISC) {
		ret = arm64_dis_misc(x);
	} else if ((grp_code & A64_GC_DATA_REG_MASK) == A64_GC_DATA_REG) {
		ret = arm64_dis_data_reg(x);
	} else if ((grp_code & A64_GC_DATA_ADV_MASK) == A64_GC_DATA_ADV) {
		ret = arm64_dis_data_adv(x);
	}

	return (ret);
}
