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

#include "fakeloader.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/elf.h>
#include <sys/atag.h>
#include <sys/pte.h>
#include <sys/sysmacros.h>

/*
 * This is the stock ARM fake uniboot loader.
 *
 * Here's what we have to do:
 *   o Read the atag header and find the combined archive header
 *   o Determine the set of mappings we need to add for the following:
 *   		- unix
 *   		- boot_archive
 *   		- atags
 *   o Enable unaligned access
 *   o Enable the caches + virtual memory
 *
 * There are several important constraints that we have here:
 *
 *   o We cannot use any .data! Several loaders that come before us are broken
 *     and only provide us with the ability to map our .text and potentially our
 *     .bss. We should strive to avoid even that if we can.
 */

#ifdef	DEBUG
#define	FAKELOAD_DPRINTF(x)	fakeload_puts(x)
#else
#define	FAKELOAD_DPRINTF(x)
#endif 	/* DEBUG */

/*
 * XXX ASSUMES WE HAVE Free memory following the boot archive
 */
static uintptr_t freemem;
static uint32_t *pt_addr;

/* Simple copy routines */
void
bcopy(const void *s, void *d, size_t n)
{
	const char *src = s;
	char *dest = d;

	if (n == 0 || s == d)
		return;

	if (dest < src && dest + n < src) {
		/* dest overlaps with the start of src, copy forward */
		for (; n > 0; n--, src++, dest++)
			*dest = *src;
	} else {
		/* src overlaps with start of dest or no overlap, copy rev */
		src += n - 1;
		dest += n - 1;
		for (; n > 0; n--, src--, dest--)
			*dest = *src;
	}
}

void
bzero(void *s, size_t n)
{
	char *c = s;
	while (n > 0) {
		*c = 0;
		c++;
		n--;
	}
}

static void
fakeload_puts(const char *str)
{
	while (*str != '\0') {
		fakeload_backend_putc(*str);
		str++;
	}
}

static void
fakeload_panic(const char *reason)
{
	fakeload_puts("panic!\n");
	fakeload_puts(reason);
	fakeload_puts("\n");
	fakeload_puts("spinning forever... goodbye...\n");
	for (;;)
		;
}

static void
fakeload_ultostr(unsigned long value)
{
	char buf[16];
	ulong_t t, val = (ulong_t)value;
	char c;
	char *ptr = &(buf[14]);
	buf[15] = '\0';

	do {
		c = (char)('0' + val - 16 * (t = (val >> 4)));
		if (c > '9')
			c += 'A' - '9' - 1;
		*--ptr = c;
	} while ((val = t) != 0);

	*--ptr = 'x';
	*--ptr = '0';
	fakeload_puts(ptr);
}

static void
fakeload_selfmap(atag_header_t *chain)
{
	atag_illumos_mapping_t aim;

	aim.aim_header.ah_size = ATAG_ILLUMOS_MAPPING_SIZE;
	aim.aim_header.ah_tag = ATAG_ILLUMOS_MAPPING;
	aim.aim_paddr = 0x7000;
	aim.aim_vaddr = aim.aim_paddr;
	aim.aim_plen = 0x3000;
	aim.aim_vlen = aim.aim_plen;
	aim.aim_mapflags = PF_R | PF_X;
	atag_append(chain, &aim.aim_header);
}

/*
 * This is our generally entry point. We're passed in the entry point of the
 * header.
 */
static uintptr_t
fakeload_archive_mappings(atag_header_t *chain, const void *addr)
{
	atag_illumos_mapping_t aim;
	fakeloader_hdr_t *hdr;
	Elf32_Ehdr *ehdr;
	Elf32_Phdr *phdr;
	int nhdrs, i;
	uintptr_t ret;

	hdr = (fakeloader_hdr_t *)addr;

	if (hdr->fh_magic[0] != FH_MAGIC0)
		fakeload_panic("fh_magic[0] is wrong!\n");
	if (hdr->fh_magic[1] != FH_MAGIC1)
		fakeload_panic("fh_magic[1] is wrong!\n");
	if (hdr->fh_magic[2] != FH_MAGIC2)
		fakeload_panic("fh_magic[2] is wrong!\n");
	if (hdr->fh_magic[3] != FH_MAGIC3)
		fakeload_panic("fh_magic[3] is wrong!\n");

	if (hdr->fh_unix_size == 0)
		fakeload_panic("hdr unix size is zero\n");
	if (hdr->fh_unix_offset == 0)
		fakeload_panic("hdr unix offset is zero\n");
	if (hdr->fh_archive_size == 0)
		fakeload_panic("hdr archive size is zero\n");
	if (hdr->fh_archive_offset == 0)
		fakeload_panic("hdr archive_offset is zero\n");

	ehdr = (Elf32_Ehdr *)((uintptr_t)addr + hdr->fh_unix_offset);

	if (ehdr->e_ident[EI_MAG0] != ELFMAG0)
		fakeload_panic("magic[0] wrong");
	if (ehdr->e_ident[EI_MAG1] != ELFMAG1)
		fakeload_panic("magic[1] wrong");
	if (ehdr->e_ident[EI_MAG2] != ELFMAG2)
		fakeload_panic("magic[2] wrong");
	if (ehdr->e_ident[EI_MAG3] != ELFMAG3)
		fakeload_panic("magic[3] wrong");
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32)
		fakeload_panic("wrong elfclass");
	if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		fakeload_panic("wrong encoding");
	if (ehdr->e_ident[EI_OSABI] != ELFOSABI_SOLARIS)
		fakeload_panic("wrong os abi");
	if (ehdr->e_ident[EI_ABIVERSION] != EAV_SUNW_CURRENT)
		fakeload_panic("wrong abi version");
	if (ehdr->e_type != ET_EXEC)
		fakeload_panic("unix is not an executable");
	if (ehdr->e_machine != EM_ARM)
		fakeload_panic("unix is not an ARM Executible");
	if (ehdr->e_version != EV_CURRENT)
		fakeload_panic("wrong version");
	if (ehdr->e_phnum == 0)
		fakeload_panic("no program headers");
	ret = ehdr->e_entry;

	FAKELOAD_DPRINTF("validated unix's headers\n");

	nhdrs = ehdr->e_phnum;
	phdr = (Elf32_Phdr *)((uintptr_t)addr + hdr->fh_unix_offset +
	    ehdr->e_phoff);
	for (i = 0; i < nhdrs; i++, phdr++) {
		if (phdr->p_type != PT_LOAD) {
			fakeload_puts("skipping non-PT_LOAD header\n");
			continue;
		}

		if (phdr->p_filesz == 0 || phdr->p_memsz == 0) {
			fakeload_puts("skipping PT_LOAD with 0 file/mem\n");
			continue;
		}

		/*
		 * Create a mapping record for this in the atags.
		 */
		aim.aim_header.ah_size = ATAG_ILLUMOS_MAPPING_SIZE;
		aim.aim_header.ah_tag = ATAG_ILLUMOS_MAPPING;
		aim.aim_paddr = (uintptr_t)addr + hdr->fh_unix_offset +
		    phdr->p_offset;
		aim.aim_plen = phdr->p_filesz;
		aim.aim_vaddr = phdr->p_vaddr;
		aim.aim_vlen = phdr->p_memsz;
		/* Round up vlen to be a multiple of 4k */
		if (aim.aim_vlen & 0xfff) {
			aim.aim_vlen &= ~0xfff;
			aim.aim_vlen += 0x1000;
		}
		aim.aim_mapflags = phdr->p_flags;
		atag_append(chain, &aim.aim_header);
	}

	/* 1:1 map the boot archive */
	aim.aim_header.ah_size = ATAG_ILLUMOS_MAPPING_SIZE;
	aim.aim_header.ah_tag = ATAG_ILLUMOS_MAPPING;
	aim.aim_paddr = (uintptr_t)addr + hdr->fh_archive_offset;
	aim.aim_plen = hdr->fh_archive_size;
	aim.aim_vaddr = aim.aim_paddr;
	aim.aim_vlen = aim.aim_plen;
	aim.aim_mapflags = PF_R | PF_W | PF_X;
	atag_append(chain, &aim.aim_header);

	return (ret);
}

static void
fakeload_mkatags(atag_header_t *chain)
{
	atag_illumos_status_t ais;
	atag_illumos_mapping_t aim;

	bzero(&ais, sizeof (ais));
	bzero(&aim, sizeof (aim));

	ais.ais_header.ah_size = ATAG_ILLUMOS_STATUS_SIZE;
	ais.ais_header.ah_tag = ATAG_ILLUMOS_STATUS;
	atag_append(chain, &ais.ais_header);
	aim.aim_header.ah_size = ATAG_ILLUMOS_MAPPING_SIZE;
	aim.aim_header.ah_tag = ATAG_ILLUMOS_MAPPING;
	atag_append(chain, &aim.aim_header);
}

static uintptr_t
fakeload_alloc_l2pt(void)
{
	uintptr_t ret;

	if (freemem & ARMPT_L2_MASK) {
		ret = freemem;
		ret &= ~ARMPT_L2_MASK;
		ret += ARMPT_L2_SIZE;
		freemem = ret + ARMPT_L2_SIZE;
	} else {
		ret = freemem;
		freemem = ret + ARMPT_L2_SIZE;
	}

	bzero((void *)ret, ARMPT_L2_SIZE);
	return (ret);
}

/*
 * Finally, do all the dirty work. Let's create some page tables. The L1 page
 * table is full of 1 MB mappings by default. The L2 Page table is 1k in size
 * and covers that 1 MB. We're going to always create L2 page tables for now
 * which will use 4k and 64k pages.
 */
static void
fakeload_map(armpte_t *pt, uintptr_t pstart, uintptr_t vstart, size_t len,
    uint32_t prot)
{
	int entry, chunksize;
	armpte_t *pte, *l2pt;
	arm_l1pt_t *l1pt;

	/*
	 * Make sure both pstart + vstart are 4k aligned, along with len.
	 */
	if (pstart & 0xfff)
		fakeload_panic("pstart is not 4k aligned");
	if (vstart & 0xfff)
		fakeload_panic("vstart is not 4k aligned");
	if (len & 0xfff)
		fakeload_panic("len is not 4k aligned");

	/*
	 * We're going to logically deal with each 1 MB chunk at a time.
	 */
	while (len > 0) {
		if (vstart & 0xfffff) {
			chunksize = MIN(len, 0x100000 - (vstart & 0xfffff));
		} else {
			chunksize = MIN(len, 0x100000);
		}

		entry = ARMPT_VADDR_TO_L1E(vstart);
		pte = &pt[entry];

		if (!ARMPT_L1E_ISVALID(*pte)) {
			uintptr_t l2table;

			l2table = fakeload_alloc_l2pt();
			*pte = 0;
			l1pt = (arm_l1pt_t *)pte;
			l1pt->al_type = ARMPT_L1_TYPE_L2PT;
			l1pt->al_ptaddr = ARMPT_ADDR_TO_L1PTADDR(l2table);
		} else if ((*pte & ARMPT_L1_TYPE_MASK) != ARMPT_L1_TYPE_L2PT) {
			fakeload_panic("encountered l1 entry that's not a "
			    "pointer to a level 2 table\n");
		} else {
			l1pt = (arm_l1pt_t *)pte;
		}

		/* Now that we have the l1pt fill in l2 entries */
		l2pt = (void *)(l1pt->al_ptaddr << ARMPT_L1PT_TO_L2_SHIFT);
		len -= chunksize;
		while (chunksize > 0) {
			arm_l2e_t *l2pte;

			entry = ARMPT_VADDR_TO_L2E(vstart);
			pte = &l2pt[entry];

			if ((*pte & ARMPT_L2_TYPE_MASK) !=
			    ARMPT_L2_TYPE_INVALID)
				fakeload_panic("found existing l2 page table, "
				    "overlap in requested mappings detected!");
			/* Map vaddr to our paddr! */
			l2pte = ((arm_l2e_t *)pte);
			*pte = 0;
			if (!(prot & PF_X))
				l2pte->ale_xn = 1;
			l2pte->ale_ident = 1;
			if (prot & PF_DEVICE) {
				l2pte->ale_bbit = 1;
				l2pte->ale_cbit = 0;
				l2pte->ale_tex = 0;
				l2pte->ale_sbit = 1;
			} else {
				l2pte->ale_bbit = 1;
				l2pte->ale_cbit = 1;
				l2pte->ale_tex = 1;
				l2pte->ale_sbit = 1;
			}
			if (prot & PF_W) {
				l2pte->ale_ap2 = 1;
				l2pte->ale_ap = 1;
			} else {
				l2pte->ale_ap2 = 0;
				l2pte->ale_ap = 1;
			}
			l2pte->ale_ngbit = 0;
			l2pte->ale_addr = ARMPT_PADDR_TO_L2ADDR(pstart);

			chunksize -= 4096;
			vstart += 4096;
			pstart += 4096;
		}
	}
}

static void
fakeload_create_map(armpte_t *pt, atag_illumos_mapping_t *aimp)
{
#ifdef MAP_DEBUG
	fakeload_puts("paddr->vaddr\n");
	fakeload_ultostr(aimp->aim_paddr);
	fakeload_puts("->");
	fakeload_ultostr(aimp->aim_vaddr);
	fakeload_puts("\n");
	fakeload_puts("plen-vlen\n");
	fakeload_ultostr(aimp->aim_plen);
	fakeload_puts("-");
	fakeload_ultostr(aimp->aim_vlen);
	fakeload_puts("\n");
#endif /* MAP_DEBUG */

	/*
	 * Can we map this in place or do we need to basically allocate a new
	 * region and bcopy everything into place for proper alignment?
	 *
	 * Criteria for this: we have a vlen > plen. plen is not page aligned.
	 */
	if (aimp->aim_vlen > aimp->aim_plen || (aimp->aim_paddr & 0xfff) != 0) {
		uintptr_t start;

		if (aimp->aim_mapflags & PF_NORELOC)
			fakeload_panic("tried to reloc unrelocatable mapping");
#ifdef	MAP_DEBUG
		FAKELOAD_DPRINTF("reloacting paddr\n");
#endif
		start = freemem;
		if (start & 0xfff) {
			start &= ~0xfff;
			start += 0x1000;
			bcopy((void *)aimp->aim_paddr, (void *)start,
			    aimp->aim_plen);
			if (aimp->aim_vlen > aimp->aim_plen) {
				bzero((void *)(start + aimp->aim_plen),
				    aimp->aim_vlen - aimp->aim_vlen);
			}
		}
		aimp->aim_paddr = start;
		freemem = start + aimp->aim_vlen;
#ifdef MAP_DEBUG
		fakeload_puts("new paddr: ");
		fakeload_ultostr(start);
		fakeload_puts("\n");
#endif /* MAP_DEBUG */
	}

	/*
	 * Now that everything has been set up, go ahead and map the new region.
	 */
	fakeload_map(pt, aimp->aim_paddr, aimp->aim_vaddr, aimp->aim_vlen,
	    aimp->aim_mapflags);
#ifdef MAP_DEBUG
	FAKELOAD_DPRINTF("\n");
#endif /* MAP_DEBUG */
}

void
fakeload_init(void *ident, void *ident2, void *atag)
{
	atag_header_t *hdr;
	atag_header_t *chain = (atag_header_t *)atag;
	const atag_initrd_t *initrd;
	atag_illumos_status_t *aisp;
	atag_illumos_mapping_t *aimp;
	uintptr_t unix_start;

	fakeload_backend_init();
	fakeload_puts("Hello from the loader\n");
	initrd = (atag_initrd_t *)atag_find(chain, ATAG_INITRD2);
	if (initrd == NULL)
		fakeload_panic("missing the initial ramdisk\n");

	/*
	 * Create the status atag header and the initial mapping record for the
	 * atags. We'll hold onto both of these.
	 */
	fakeload_mkatags(chain);
	aisp = (atag_illumos_status_t *)atag_find(chain, ATAG_ILLUMOS_STATUS);
	if (aisp == NULL)
		fakeload_panic("can't find ATAG_ILLUMOS_STATUS");
	aimp = (atag_illumos_mapping_t *)atag_find(chain, ATAG_ILLUMOS_MAPPING);
	if (aimp == NULL)
		fakeload_panic("can't find ATAG_ILLUMOS_MAPPING");
	FAKELOAD_DPRINTF("created proto atags\n");

	/*
	 * Set freemem to be 16 KB aligned at the end of freemem.
	 */
	freemem = initrd->ai_start + initrd->ai_size;
	freemem &= ~ARMPT_L1_MASK;
	freemem += ARMPT_L1_SIZE;

	fakeload_selfmap(chain);

	/*
	 * Map the boot archive and all of unix
	 */
	unix_start = fakeload_archive_mappings(chain,
	    (const void *)(uintptr_t)initrd->ai_start);
	FAKELOAD_DPRINTF("filled out unix and the archive's mappings\n");

	/*
	 * Fill in the atag mapping header for the atags themselves. 1:1 map it.
	 */
	aimp->aim_paddr = (uintptr_t)chain & ~0xfff;
	aimp->aim_plen = atag_length(chain) & ~0xfff;
	aimp->aim_plen += 0x1000;
	aimp->aim_vaddr = aimp->aim_paddr;
	aimp->aim_vlen = aimp->aim_plen;
	aimp->aim_mapflags = PF_R | PF_W | PF_NORELOC;

	/*
	 * Let the backend add mappings
	 */
	fakeload_backend_addmaps(chain);

	/*
	 * Turn on unaligned access
	 */
	FAKELOAD_DPRINTF("turning on unaligned access\n");
	fakeload_unaligned_enable();
	FAKELOAD_DPRINTF("successfully enabled unaligned access\n");

	/*
	 * To turn on the MMU we need to do the following:
	 *  o Program all relevant CP15 registers
	 *  o Program 1st and 2nd level page tables
	 *  o Invalidate and Disable the I/D-cache
	 *  o Fill in the last bits of the ATAG_ILLUMOS_STATUS atag
	 *  o Turn on the MMU in SCTLR
	 *  o Jump to unix
	 */

	/* Last bits of the atag */
	aisp->ais_freemem = freemem;
	pt_addr = (void *)freemem;
	freemem += sizeof (uint32_t) * 4096;
	aisp->ais_version = 1;
	aisp->ais_ptbase = (uintptr_t)pt_addr;

	/* Set up the l1 page table by first invalidating it */
	bzero(pt_addr, sizeof (uint32_t) * 4096);

	/*
	 * Our initial page table is a series of 1 MB sections. While we really
	 * should map 4k pages, for the moment we're just going to map 1 MB
	 * regions, yay team!
	 */
	hdr = chain;
	FAKELOAD_DPRINTF("creating mappings\n");
	while (hdr != NULL) {
		if (hdr->ah_tag == ATAG_ILLUMOS_MAPPING)
			fakeload_create_map(pt_addr,
			    (atag_illumos_mapping_t *)hdr);
		hdr = atag_next(hdr);
	}

	/* Now that we've mapped, update freeused */
	aisp->ais_freeused = freemem - aisp->ais_freemem;

	/* Cache disable */
	FAKELOAD_DPRINTF("Flushing and disabling caches\n");
	armv6_dcache_flush();
	armv6_dcache_disable();
	armv6_dcache_inval();
	armv6_icache_disable();
	armv6_icache_inval();

	/* Program the page tables */
	FAKELOAD_DPRINTF("programming cp15 regs\n");
	fakeload_pt_setup((uintptr_t)pt_addr);


	/* MMU Enable */
	FAKELOAD_DPRINTF("see you on the other side\n");
	fakeload_mmu_enable();

	FAKELOAD_DPRINTF("why helo thar\n");

	/* Renable caches */
	armv6_dcache_enable();
	armv6_icache_enable();

	/* we should never come back */
	fakeload_exec(unix_start);
	fakeload_panic("hit the end of the world\n");
}
