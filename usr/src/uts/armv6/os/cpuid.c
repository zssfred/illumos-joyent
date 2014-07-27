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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/cpuid_impl.h>
#include <sys/param.h>
#include <sys/bootconf.h>
#include <vm/vm_dep.h>
#include <sys/armv6_bsmf.h>

/*
 * Handle classification and identification of ARM processors.
 *
 * Currently we do a single pass which reads in information and asserts that the
 * basic information which we receive here matches what we'd expect and are able
 * to do everything that we need with this ARM CPU.
 *
 * TODO We'll eventually do another pass to make sure that we properly determine
 * the feature set to expose to userland.
 */

static arm_cpuid_t cpuid_data0;

static void
cpuid_parse_stage(uint32_t line, uint32_t mask, uint32_t shift, int *out)
{
	*out = (line & mask) >> shift;
}

static void
cpuid_fill_main(arm_cpuid_t *cpd)
{
	cpd->ac_pfr[0] = arm_cpuid_pfr0();
	cpd->ac_pfr[1] = arm_cpuid_pfr1();
	cpd->ac_dfr = arm_cpuid_dfr0();
	cpd->ac_mmfr[0] = arm_cpuid_mmfr0();
	cpd->ac_mmfr[1] = arm_cpuid_mmfr1();
	cpd->ac_mmfr[2] = arm_cpuid_mmfr2();
	cpd->ac_mmfr[3] = arm_cpuid_mmfr3();
	cpd->ac_isar[0] = arm_cpuid_isar0();
	cpd->ac_isar[1] = arm_cpuid_isar1();
	cpd->ac_isar[2] = arm_cpuid_isar2();
	cpd->ac_isar[3] = arm_cpuid_isar3();
	cpd->ac_isar[4] = arm_cpuid_isar4();
	cpd->ac_isar[5] = arm_cpuid_isar5();
}

static void
cpuid_fill_fpu(arm_cpuid_t *cpd)
{
	cpd->ac_mvfr[0] = arm_cpuid_mvfr0();
	cpd->ac_mvfr[1] = arm_cpuid_mvfr1();
}

#define	CACHE_LEN_MASK		0x003
#define	CACHE_M_BIT		0x004
#define	CACHE_ASSOC_MASK	0x038
#define	CACHE_ASSOC_SHIFT	3
#define	CACHE_SIZE_MASK		0x3c0
#define	CACHE_SIZE_SHIFT	6
#define	CACHE_COLOR_BIT		0x800
#define	CACHE_MASK		0xfff
#define	CACHE_DCACHE_SHIFT	12
#define	CACHE_SEPARATE		0x1000000

/*
 * On ARMv6 the value of the cache size and the cache associativity depends on
 * the value of the M bit, which modifies the value that's in the actual index.
 */
static uint32_t armv6_cpuid_cache_sizes[2][9] = {
	{ 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 0x8000, 0x100000,
		0x20000 },
	{ 0x300, 0x600, 0xc00, 0x1800, 0x3000, 0x6000, 0xc000, 0x18000,
		0x30000 }
};

static int8_t armv6_cpuid_cache_assoc[2][9] = {
	{ 1, 2, 4, 8, 16, 32, 64, 128 },
	{ -1, 3, 6, 12, 24, 48, 96, 192 }
};

static uint8_t armv6_cpuid_cache_linesz[] = {
	8,
	16,
	32,
	64
};

static void
cpuid_fill_onecache(arm_cpuid_cache_t *accp, uint32_t val)
{
	int mbit, index, assoc;

	mbit = (val & CACHE_M_BIT) != 0 ? 1 : 0;
	index = (val & CACHE_ASSOC_MASK) >> CACHE_ASSOC_SHIFT;
	assoc = armv6_cpuid_cache_assoc[mbit][index];
	if (assoc == -1) {
		accp->acc_exists = B_FALSE;
		return;
	}
	ASSERT(assoc > 0);
	accp->acc_assoc = assoc;
	accp->acc_rcolor = (val & CACHE_COLOR_BIT) == 0 ?
	    B_FALSE : B_TRUE;
	index = val & CACHE_LEN_MASK;
	accp->acc_linesz = armv6_cpuid_cache_linesz[index];
	index = (val & CACHE_SIZE_MASK) >> CACHE_SIZE_SHIFT;
	accp->acc_size = armv6_cpuid_cache_sizes[mbit][index];
	accp->acc_exists = B_TRUE;
}

static void
cpuid_fill_caches(arm_cpuid_t *cpd)
{
	uint32_t val, icache, dcache;

	val = arm_cpuid_ctr();
	icache = val & CACHE_MASK;
	cpuid_fill_onecache(&cpd->ac_icache, icache);
	dcache = (val >> CACHE_DCACHE_SHIFT) & CACHE_MASK;
	cpuid_fill_onecache(&cpd->ac_dcache, dcache);

	if (val & CACHE_SEPARATE) {
		cpd->ac_unifiedl1 = B_FALSE;
	} else {
		cpd->ac_unifiedl1 = B_TRUE;
	}

	armv6_bsmdep_l2cacheinfo();
	armv6_cachesz = cpd->ac_dcache.acc_size;
	armv6_cache_assoc = cpd->ac_dcache.acc_assoc;
}


/*
 * There isn't a specific way to indicate that we're on ARMv6k. Instead what we
 * need to do is go through and check for a few features that we know we're
 * going to need.
 *
 * TODO This will have to be revisited with ARMv7 support
 */
static void
cpuid_verify(void)
{
	arm_cpuid_mem_vmsa_t vmsa;
	arm_cpuid_mem_barrier_t barrier;
	int sync, syncf;

	arm_cpuid_t *cpd = &cpuid_data0;

	/* v6 vmsa */
	cpuid_parse_stage(cpd->ac_mmfr[0], ARM_CPUID_MMFR0_STATE0_MASK,
	    ARM_CPUID_MMFR0_STATE0_SHIFT, (int *)&vmsa);
	/* TODO We might be able to support v6, but bcm2835+qvpb are this */
	if (vmsa != ARM_CPUID_MEM_VMSA_V7) {
		bop_printf(NULL, "invalid vmsa setting, found 0x%x\n", vmsa);
		bop_panic("unsupported cpu");
	}

	/* check for ISB, DSB, etc. in cp15 */
	cpuid_parse_stage(cpd->ac_mmfr[2], ARM_CPUID_MMFR2_STATE5_MASK,
	    ARM_CPUID_MMFR2_STATE5_SHIFT, (int *)&barrier);
	if (barrier != ARM_CPUID_MEM_BARRIER_CP15 &&
	    barrier != ARM_CPUID_MEM_BARRIER_INSTR) {
		bop_printf(NULL, "missing support for CP15 memory barriers\n");
		bop_panic("unsupported CPU");
	}

	/* synch prims */
	cpuid_parse_stage(cpd->ac_isar[4], ARM_CPUID_ISAR3_STATE3_SHIFT,
	    ARM_CPUID_ISAR4_STATE5_SHIFT, (int *)&sync);
	cpuid_parse_stage(cpd->ac_isar[4], ARM_CPUID_ISAR4_STATE3_SHIFT,
	    ARM_CPUID_ISAR4_STATE5_SHIFT, (int *)&syncf);
	if (sync != 0x2 && syncf != 0x0) {
		bop_printf(NULL, "unsupported synch primitives: sync,frac: "
		    "%x,%x\n", sync, syncf);
		bop_panic("unsupported CPU");
	}

	if (cpd->ac_icache.acc_exists == B_FALSE) {
		bop_printf(NULL, "icache not defined to exist\n");
		bop_panic("unsupported CPU");
	}

	if (cpd->ac_dcache.acc_exists == B_FALSE) {
		bop_printf(NULL, "dcache not defined to exist\n");
		bop_panic("unsupported CPU");
	}
}

static void
cpuid_valid_ident(uint32_t ident)
{
	arm_cpuid_ident_arch_t arch;

	/*
	 * We don't support stock ARMv6 or older.
	 */
	arch = (ident & ARM_CPUID_IDENT_ARCH_MASK) >>
	    ARM_CPUID_IDENT_ARCH_SHIFT;
	if (arch != ARM_CPUID_IDENT_ARCH_CPUID) {
		bop_printf(NULL, "encountered unsupported CPU arch: 0x%x",
		    arch);
		bop_panic("unsupported CPU");
	}
}

static void
cpuid_valid_fpident(uint32_t ident)
{
	arm_cpuid_vfp_arch_t vfp;

	cpuid_parse_stage(ident, ARM_CPUID_VFP_ARCH_MASK,
	    ARM_CPUID_VFP_ARCH_SHIFT, (int *)&vfp);
	if (vfp != ARM_CPUID_VFP_ARCH_V2) {
		bop_printf(NULL, "unsupported vfp version: %x\n", vfp);
		bop_panic("unsupported CPU");
	}

	if ((ident & ARM_CPUID_VFP_SW_MASK) != 0) {
		bop_printf(NULL, "encountered software-only vfp\n");
		bop_panic("unsuppored CPU");
	}
}
void
cpuid_setup(void)
{
	arm_cpuid_t *cpd = &cpuid_data0;

	cpd->ac_ident = arm_cpuid_idreg();
	cpuid_valid_ident(cpd->ac_ident);
	cpuid_fill_main(cpd);

	cpd->ac_fpident = arm_cpuid_vfpidreg();
	cpuid_valid_fpident(cpd->ac_fpident);
	cpuid_fill_fpu(cpd);
	cpuid_fill_caches(cpd);

	cpuid_verify();
}
