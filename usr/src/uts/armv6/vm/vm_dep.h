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

#ifndef _VM_DEP_H
#define	_VM_DEP_H

/*
 * UNIX machine dependent virtual memory support for ARMv6.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/param.h>

/*
 * Do not use GETTICK. It is only meant to be used when timesource
 * synchronization is unimportant.
 */
#define	GETTICK()	gethrtime_unscaled()

#define	PLCNT_SZ(ctrs_sz)	panic("plcnt_sz")

#define	PLCNT_INIT(addr) panic("plcnt_init")

#define	PLCNT_INCR(pp, mnode, mtype, szc, flags)	panic("plcnt_incr")
#define	PLCNT_DECR(pp, mnode, mtype, szc, flags)	panic("plcnt_decr")

/*
 * Macro to update page list max counts. This is a no-op on x86, not on SPARC.
 * We panic for now on ARM. It's primarily used for kcage it appears.
 */
#define	PLCNT_XFER_NORELOC(pp)		panic("plcnt_xfer_noreloc")

/*
 * Macro to modify the page list max counts when memory is added to
 * the page lists during startup (add_physmem) or during a DR operation
 * when memory is added (kphysm_add_memory_dynamic) or deleted
 * (kphysm_del_cleanup).
 */
extern void plcnt_modify_max(pfn_t, long);
#define	PLCNT_MODIFY_MAX(pfn, cnt)	mtype_modify_max(pfn, cnt)

/*
 * These macros are used in dealing with the page counters and its candidate
 * counters. These are used as a part of coalescing our free lists.
 */

/*
 * The maximum number of memory ranges that exist in the system. Consider i86pc,
 * there we have various ranges that exist due to legacy DMA. eg. < 16 Mb, < 4
 * Gb for PCI, etc. Like sun4, this may actually just be a single number, since
 * unlike on sun4, we're not going to pretend we have a kcage.
 */
#define	MAX_MNODE_MRANGES	panic("max_mnodes_mranges")
#define	MNODE_RANGE_CNT		panic("monde_range_cnt")
#define	MNODE_MAX_RANGE		panic("mnode_max_range")
#define	MNODE_2_RANGE		panic("mnode_2_range")


/*
 * XXX These are strawman definitions based on the i86pc versions of the
 * page_freelists and the page_cachelists. We index into the freelist by
 * [mtype][mmu_page_sizes][colors]. We index into the cachelist by
 * [mtype][colors]. However, for the moment we're going to just panic when using
 * the macros to access them.
 */
extern page_t ****page_freelists;
extern page_t ***page_cachelists;

#define	PAGE_FREELISTS(mnode, szc, color, mtype)	panic("page_freelists")
#define	PAGE_CACHELISTS(mnode, szc, color, mtype)	panic("page_cachelists")

/*
 * XXX This set of locks needs to be rethought with respect to mandatory page
 * coloring. It was taken rather naively from i86pc
 */

/*
 * There are mutexes for both the page freelist
 * and the page cachelist.  We want enough locks to make contention
 * reasonable, but not too many -- otherwise page_freelist_lock() gets
 * so expensive that it becomes the bottleneck!
 */

#define	NPC_MUTEX	16

extern kmutex_t	*fpc_mutex[NPC_MUTEX];
extern kmutex_t	*cpc_mutex[NPC_MUTEX];

#define	FPC_MUTEX(mnode, i)	(&fpc_mutex[i][mnode])
#define	CPC_MUTEX(mnode, i)	(&cpc_mutex[i][mnode])

/*
 * Memory node iterators. We may need something here related to colors, but we
 * may not. For the time being, just panic on use for ust to get back to later.
 */
#define	MEM_NODE_ITERATOR_DECL(it)	panic("mem_node_iterator_decl")
#define	MEM_NODE_ITERATOR_INIT(pfn, mnode, szc, it)	panic("mem_node_iterator_init")

/*
 * XXX Do we ever interleave memory ndoes on armv6? Probably not? Does coloring
 * come into play here?
 */
#define	HPM_COUNTERS_LIMITS(mnodes, pyysbase, physmax, first)	\
	panic("hpm_counters_list")

#define	PAGE_CTRS_WRITE_LOCK(mnode)	panic("page_ctrs_write_lock")
#define	PAGE_CTRS_WRITE_UNLOCK(mnode)	panic("page_ctrs_write_unlock")
#define	PAGE_CTRS_ADJUST(pfn, cnt, rv)	panic("page_cntrs_adjust")

/*
 * Coloring related macros
 */
#define	PAGE_GET_COLOR_SHIFT(pfn, cnt, rv)	panic("page_get_color_shift")
#define	PAGE_CONVERT_COLOR(ncolor, szc, nszc)	panic("page_convert_color")
#define	PFN_2_COLOR(pfn, szc, it)		panic("pfn_2_color")

#define	PNUM_SIZE(szc)	panic("pnum_size")
#define	PNUM_SHIFT(szc)	panic("pnum_shift")
#define	PAGE_GET_SHIFT(szc)	panic("page_get_shift")
#define	PAGE_GET_PAGECOLORS(szc)	panic("page_get_pagecolors")

#define	PAGE_NEXT_PFN_FOR_COLOR(pfn, szc, color, ceq_mask, color_mask, it) \
	panic("page_next_pfn_for_color")

#define	PAGE_GET_NSZ_MASK(szc, mask)	panic("page_get_nsz_mask")
#define	PAGE_GET_NSZ_COLOR(szc, color)	panic("page_get_nsz_mask")

#define	PP_2_BIN_SZC(pp, szc)	panic("pp_2_bin_szc")
#define	PP_2_BIN(pp)		panic("pp_2_bin")	
#define	PP_2_MEM_NODE(pp)	panic("pp_2_mem_node")	
#define	PP_2_MTYPE(pp)		panic("pp_2_mtype")	

#define	PFN_BASE(pfnum, szc)	panic("pfn_base")

/*
 * XXX These are total strawmen based on i86pc and sun4 for walking the page
 * tables.
 */
typedef struct page_list_walker {
	uint_t	plw_colors;		/* num of colors for szc */
	uint_t  plw_color_mask;		/* colors-1 */
	uint_t	plw_bin_step;		/* next bin: 1 or 2 */
	uint_t  plw_count;		/* loop count */
	uint_t	plw_bin0;		/* starting bin */
	uint_t  plw_bin_marker;		/* bin after initial jump */
	uint_t  plw_bin_split_prev;	/* last bin we tried to split */
	uint_t  plw_do_split;		/* set if OK to split */
	uint_t  plw_split_next;		/* next bin to split */
	uint_t	plw_ceq_dif;		/* number of different color groups */
					/* to check */
	uint_t	plw_ceq_mask[MMU_PAGE_SIZES + 1]; /* color equiv mask */
	uint_t	plw_bins[MMU_PAGE_SIZES + 1];	/* num of bins */
} page_list_walker_t;

extern void page_list_walk_init(uchar_t szc, uint_t flags, uint_t bin,
    int can_split, int use_ceq, page_list_walker_t *plw);

/*
 * XXX memory type initializaiton
 */
#define	MTYPE_INIT(mtype, vp, vaddr, flags, pgsz)	panic("mtype_init")
#define	MTYPE_START(mnode, mtype, flags)	panic("mtype_start")
#define	MTYPE_NEXT(mnode, mtype, flags)	panic("mtype_next")
#define	MTYPE_PGR_INIT(mtype, flags, pp, mnode, pgcnt)	panic("mtype_pgr_init")
#define	MNODETYPE_2_PFN(mnode, mtype, pfnlo, pfnhi)	panic("mnodetype_2_pfn")
#define	PC_BIN_MUTEX(mnode, bin, flags) ((flags & PG_FREE_LIST)	panic("pc_bin_mutex")

#ifdef DEBUG
#define	CHK_LPG(pp, szc)	panic("chk_lpg")
#else
#define	CHK_LPG(pp, szc)
#endif

#define	FULL_REGION_CNT(rg_szc)	panic("full_region_cnt")
#define	PP_GROUPLEADER(pp, szc)	panic("pp_groupleader")
#define	PP_PAGEROOT(pp)	panic("pp_pageroot")


#define	PC_BASE_ALIGN	panic("pc_base_align")
#define	PC_BASE_ALIGN_MASK	panic("pc_base_align_mask")
#define	USERSZC_2_SZC(userszc)	panic("userszc_2_szc")
#define	SZC_2_USERSZC(szc)	panic("szc_2_userszc")

#define	L2CACHE_ALIGN		panic("l2cache_align")
#define	L2CACHE_ALIGN_MAX	panic("l2cache_align_max")
#define	CPUSETSIZE()		panic("cpusetsize")
#define	PAGE_BSZS_SHIFT(szc)	panic("page_bszs_shift")

/*
 * Internal PG_ flags.
 */
#define	PGI_RELOCONLY	0x010000	/* opposite of PG_NORELOC */
#define	PGI_NOCAGE	0x020000	/* cage is disabled */
#define	PGI_PGCPHIPRI	0x040000	/* page_get_contig_page pri alloc */
#define	PGI_PGCPSZC0	0x080000	/* relocate base pagesize page */

/*
 * XXX Consider PGI flags for ourselves
 */

#define	AS_2_BIN(as, seg, vp, addr, bin, szc)	panic("as_2_bin")
#define	VM_CPU_DATA_PADSIZE	panic("vm_cpu_data_padsize")

#ifdef __cplusplus
}
#endif

#endif /* _VM_DEP_H */
