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

#include <libdisasm.h>
#include <stdio.h>
#include <string.h>

#include "dis_arm64_decoder.h"
#include "libdisasm_impl.h"

static int
dis_arm64_supports_flags(int flags)
{
	int archflags = flags & DIS_ARCH_MASK;

	if (archflags == DIS_ARM_V8)
		return (1);

	return (0);
}

static int
dis_arm64_disassemble(dis_handle_t *dhp, uint64_t addr, char *buf,
    size_t buflen)
{
	int err;
	arm64ins_t x;
	(void) memset(&x, 0, sizeof (arm64ins_t));

	dhp->dh_addr = addr;
	x.a64_pc = addr;
	if (dhp->dh_read(dhp->dh_data, addr, &x.a64_instr, 4) != 4)
		return (-1);

	err = arm64_decode(&x);
	if (err != 0) {
		return (err);
	}
	arm64_format_instr(&x, buf, buflen, dhp);
	return (0);
}

/* ARGSUSED */
static uint64_t
dis_arm64_previnstr(dis_handle_t *dhp, uint64_t pc, int n)
{
	if (n <= 0)
		return (pc);

	return (pc - n*4);
}

/* ARGSUSED */
static int
dis_arm64_min_instrlen(dis_handle_t *dhp)
{
	return (4);
}

/* ARGSUSED */
static int
dis_arm64_max_instrlen(dis_handle_t *dhp)
{
	return (4);
}

/* ARGSUSED */
static int
dis_arm64_instrlen(dis_handle_t *dhp, uint64_t pc)
{
	return (4);
}

dis_arch_t dis_arch_arm64 = {
	.da_supports_flags	= dis_arm64_supports_flags,
	.da_disassemble		= dis_arm64_disassemble,
	.da_previnstr		= dis_arm64_previnstr,
	.da_min_instrlen	= dis_arm64_min_instrlen,
	.da_max_instrlen	= dis_arm64_max_instrlen,
	.da_instrlen		= dis_arm64_instrlen,
};
