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

#include <sys/param.h>
#include <sys/bootconf.h>
#include <sys/atag.h>
#include <sys/pte.h>
#include <sys/elf.h>

/*
 * Routines for mainpulating page tables during fakebop.
 */

/* Root of the boot page table */
static armpte_t *armboot_pt;

/*
 * Get the root of the page table the loader gave us. Go through and remove the
 * mappings from the loader so we can reuse that physical memory.
 */
void
armboot_mmu_init(atag_header_t *chain)
{
	atag_illumos_status_t *aisp;

	aisp = (atag_illumos_status_t *)atag_find(chain, ATAG_ILLUMOS_STATUS);
	if (aisp == NULL)
		bop_panic("missing ATAG_ILLUMOS_STATUS!\n");
	armboot_pt = (armpte_t *)(uintptr_t)aisp->ais_ptbase;
	/* XXX Unmap the loader region */
}

static void
armboot_mmu_map_1mb(uintptr_t pa, uintptr_t va, int prot)
{
	int entry;
	armpte_t *pte;
	armpte_t ptt;
	arm_l1s_t *l1e;

	entry = ARMPT_VADDR_TO_L1E(va);
	pte = &armboot_pt[entry];
	if (ARMPT_L1E_ISVALID(*pte))
		bop_panic("armboot_mmu: asked to map a mapped region!\n");
	ptt = 0;
	l1e = (arm_l1s_t *)&ptt;
	l1e->al_type = ARMPT_L1_TYPE_SECT;
	/* Assume it's not device memory */
	l1e->al_bbit = 1;
	l1e->al_cbit = 1;
	l1e->al_tex = 1;
	l1e->al_sbit = 1;

	if (!(prot & PF_X))
		l1e->al_xn = 1;
	l1e->al_domain = 0;

	if (prot & PF_W) {
		l1e->al_ap2 = 1;
		l1e->al_ap = 1;
	} else {
		l1e->al_ap2 = 0;
		l1e->al_ap = 1;
	}
	l1e->al_ngbit = 0;
	l1e->al_issuper = 0;
	l1e->al_addr = ARMPT_PADDR_TO_L1SECT(pa);
	/* Now that we've set this up, assign it atomically */
	/* XXX tlb/cache maintenance? */
	*pte = ptt;
}

void
armboot_mmu_map(uintptr_t pa, uintptr_t va, size_t len, int prot)
{
	if (len & 0xfffff)
		bop_panic("need to add non-1MB aligned MMU support\n");
	if (pa & 0xfffff)
		bop_panic("need to add non-1<B aligned MMU support");
	if (va & 0xfffff)
		bop_panic("need to add non-1<B aligned MMU support");

	while (len > 0) {
		armboot_mmu_map_1mb(pa, va, prot);
		len -= 0x100000;
		pa += 0x100000;
		va += 0x100000;
	}
}
