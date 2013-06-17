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
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * ARM relocation code
 */

/*
 * TODO We've stubbed out the sdt resolve functions. No reason to even think
 * about those now. It's here so we remember it. The TNF one on the other hand
 * is being left behind. No reason to add it.
 */

static int
sdt_reloc_resolve(struct module *mp, char *symname, uint8_t *instr)
{
	return (1);
}

int
do_relocate(struct module *mp, char *reltbl, Word relshtype, int nreloc,
    int relocsize, Addr baseaddr)
{
	_kobj_printf("Implement me\n");
	return (-1);
}

int
do_relocations(struct module *mp)
{
	_kobj_printf("Implement me\n");
	return (-1);
}
