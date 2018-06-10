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

#ifndef	_DIS_ARM64_DECODER_H
#define	_DIS_ARM64_DECODER_H

#ifdef __cplusplus
extern	"C" {
#endif

#include <sys/types.h>

#include "libdisasm.h"

#define	A64_SYSREG_OPS	5
#define	A64_MAX_OPNDS	5 /* Max number of operands used by an instruction */
#define	A64_SP_REG	31

typedef enum {
	A64_NOT_USED,
	A64_GP_REG,		/* GP registers where reg 31 == XZR or WZR */
	A64_GP_REG_SP,		/* GP registers where reg 31 == SP or WSP */
	A64_SYS_UNNAMED_REG,
	A64_SYS_NAMED_REG,
	A64_IMMEDIATE,
	A64_LEFT_SHIFT,
	A64_RIGHT_SHIFT_LOG,
	A64_RIGHT_SHIFT_ARITHM,
	A64_ROTATE_SHIFT,
	A64_LABEL,
	A64_PRE_INDEX,
	A64_POST_INDEX,
	A64_REG_INDEX,
	A64_SIGNED_OFF,
	A64_CONDITION,
	A64_PREFETCH_OPTIONS,
	A64_EXTENSION,
	A64_FLAGS_STATE,
	A64_BARRIER_OP,
	A64_PSTATEFIELD,
} arm64_opnd_type_t;

typedef enum {
	A64_DONT_CARE,
	A64_32BIT,
	A64_64BIT,
} arm64_opnd_size_t;

typedef struct {
	uint8_t			a64_reg;
	arm64_opnd_size_t	a64_regsize;
	uint8_t			a64_ext_op;
	uint8_t			a64_ext_imm;
	boolean_t		a64_display_op;
	boolean_t		a64_display_imm;
} arm64_mem_reg_t;

typedef struct {
	uint8_t a64_op0;
	uint8_t a64_op1;
	uint8_t a64_cn;
	uint8_t a64_cm;
	uint8_t a64_op2;
} arm64_sys_reg_t;

typedef struct arm64_opnd {
	arm64_opnd_type_t	a64_type;

	union {
		int64_t		s_val;
		uint64_t	u_val;
		uint8_t		sysreg_ops[A64_SYSREG_OPS];
		arm64_mem_reg_t	mem_reg;
		arm64_sys_reg_t sys_reg;
	} a64_value;

	arm64_opnd_size_t	a64_bitsize;
	uint8_t			a64_base;
} arm64_opnd_t;

typedef struct arm64ins {
	uint32_t	a64_instr;
	uint64_t	a64_pc;

	const char	*a64_mnem;

	arm64_opnd_t	a64_opnds[A64_MAX_OPNDS];
	uint8_t		a64_num_opnds;
} arm64ins_t;

extern int arm64_decode(arm64ins_t *);
extern void arm64_format_instr(arm64ins_t *, char *, size_t, dis_handle_t *);

#ifdef __cplusplus
}
#endif

#endif /* _DIS_ARM64_DECODER_H */
