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
 * Copyright (c) 2015 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 */

/*
 * Just like in i86pc, we too get the joys of mimicking the SPARC boot system.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/bootconf.h>
#include <sys/boot_console.h>
#include <sys/bootsvcs.h>

#include <sys/fdt.h>
#include <sys/byteorder.h>
#include <sys/varargs.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/ctype.h>
#include <sys/bootstat.h>

static bootops_t bootop;

/*
 * XXXAARCH64: this is just a simple way to store boot information from
 * the fdt before we properly parse it
 */
typedef struct bootinfo {
	char		*bi_cmdline;
	uint64_t	bi_memstart;
	uint64_t	bi_memsize;
	uint64_t	bi_rdstart;
	uint64_t	bi_rdend;
	char		*bi_bootargs;
} bootinfo_t;

static bootinfo_t bootinfo;

static struct boot_syscalls bop_sysp = {
	bcons_getchar,
	bcons_putchar,
	bcons_ischar,
};

/*
 * Debugging macros
 */
static int have_console = 0;
static uint_t kbm_debug = 1;
#define	DBG_MSG(s)	{ if (kbm_debug && have_console) { bcons_puts(s); bcons_puts("\n"); } }

/* XXX: Thse are terrible. */
static void
fakebop_put_uint64(uint64_t in)
{
	if (!have_console) {
		return;
	}

	int j;
	char buf[19] = { '0', 'x', };
	buf[18] = 0;
	for (j = 0; j < 16; j++) {
		int rem = in % 16;
		buf[17 - j] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
		in = in/16;
	}
	bcons_puts((const char *) &buf);
}

static void
fakebop_put_uint32(uint32_t in)
{
	if (!have_console) {
		return;
	}

	int j;
	char buf[11] = { '0', 'x', };
	buf[10] = 0;
	for (j = 0; j < 8; j++) {
		int rem = in % 16;
		buf[9 - j] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
		in = in/16;
	}
	bcons_puts((const char *) &buf);
}

/*
 * bootconf.h methods. Note, it wants bop_panic/printf and boot_prop_finish in
 * addition to the bootops_t functions
 */
void
bop_panic(const char *msg)
{
	DBG_MSG("Panicing with message:\n");
	DBG_MSG(msg);
	DBG_MSG("\nSpinning forever now :(");
	for (;;)
		;
}

/*
 * Fakebop allocator
 */

// static caddr_t
// fakebop_alloc(struct bootops *bops, caddr_t virthint, size_t size, int align)
// {
// 	bop_panic("NYI: fakebop_alloc");
// 	return (NULL);
// }

///XXX: largely taken from armv7
/*
 * Fakebop Memory allocation Scheme
 *
 * Early on during boot we need to be able to allocate memory before we get the
 * normal kernel memory allocator up and running. Currently this memory is never
 * freed by the system, or so it appears. As such we take a much simpler
 * approach to the memory allocation. Mostly, we care off a region of memory
 * from the top of our physical range equal to bop_alloc_nfree which is
 * currently 64 MB. From there, allocations are given a 4-byte aligned chunks of
 * memory from bop_alloc_start until we run out of memory. Because of the lack
 * of any callers of the memory free routing in the system, we do not bother
 * with anything like a free list or even size and next pointers. This does make
 * the debugging a bit harder, but hopefully our use of this will be minimal
 * overall.
 *
 * TODO On other platforms this often includes using virtual memory instead of
 * physical memory. While it would be great to do that on ARM, let's start with
 * this strawman approach and later revamp it. The goal here is that it's meant
 * to be very simple... albeit this will probably be too simple in time to come.
 */
#define	FAKEBOP_ALLOC_SIZE	(64 * 1024 * 1024)
static uintptr_t bop_alloc_start = 0;
static uintptr_t bop_alloc_nfree = FAKEBOP_ALLOC_SIZE;
/*
 * We need to reserve bop_alloc_nfree bytes from the top of our memory range. We
 * also need to make sure that nothing else is using that region of memory, eg.
 * the initial ram disk or the kernel.
 */
static void
fakebop_alloc_init(void)
{
	uintptr_t top;

	top = bootinfo.bi_memstart + bootinfo.bi_memsize;
	top -= bop_alloc_nfree;

	if (top > bootinfo.bi_rdstart && top < bootinfo.bi_rdend)
		bop_panic("fakebop_alloc_init memory range has overlaps");
	bop_alloc_start = top;
	bop_printf(NULL, "starting with memory at 0x%x and have %d bytes\n", bop_alloc_start, bop_alloc_nfree);
}

static caddr_t
fakebop_alloc(struct bootops *bops, caddr_t virthint, size_t size, int align)
{
	caddr_t start;

	bop_printf(bops, "Asked to allocate %d bytes... ", size);
	if (bop_alloc_start == 0)
		bop_panic("fakebop_alloc_init not called");

	if (align == BO_ALIGN_DONTCARE || align == 0)
		align = 4;

	size = P2ROUNDUP(size, align);
	bop_printf(bops, "Allocating %d bytes %d free... ", size, bop_alloc_nfree);
	if (size > bop_alloc_nfree)
		bop_panic("fakebop_alloc ran out of memory\n");

	start = (caddr_t)bop_alloc_start;
	bop_alloc_start += size;
	bop_alloc_nfree -= size;

	bop_printf(bops, "Allocated at 0x%llx\n", start);
	return (start);
}

///XXX: also largely taken from armv7
typedef struct bootprop {
 	struct bootprop *bp_next;
 	char *bp_name;
 	uint_t bp_vlen;
 	char *bp_value;
 } bootprop_t;

static int fakebop_prop_debug = 1;
static bootprop_t *bprops = NULL;

static void
fakebop_setprop(char *name, int nlen, void *value, int vlen)
{
	size_t size;
	bootprop_t *bp;
	caddr_t cur;

	size = sizeof (bootprop_t) + nlen + 1 + vlen;
	cur = fakebop_alloc(NULL, NULL, size, BO_ALIGN_DONTCARE);
	bp = (bootprop_t *)cur;
	if (bprops == NULL) {
		bprops = bp;
		bp->bp_next = NULL;
	} else {
		bp->bp_next = bprops;
		bprops = bp;
	}
	cur += sizeof (bootprop_t);
	bp->bp_name = cur;
	bcopy(name, cur, nlen);
	cur += nlen;
	*cur = '\0';
	cur++;
	bp->bp_value = cur;
	bp->bp_vlen = vlen;
	if (vlen > 0)
		bcopy(value, cur, vlen);
}

static void
fakebop_setprop_string(char *name, char *value)
{
	if (fakebop_prop_debug)
		bop_printf(NULL, "setprop_string: %s->[%s]\n", name, value);
	fakebop_setprop(name, strlen(name), value, strlen(value) + 1);
}

static void
fakebop_setprop_32(char *name, uint32_t value)
{
	if (fakebop_prop_debug)
		bop_printf(NULL, "setprop_32: %s->[%d]\n", name, value);
	fakebop_setprop(name, strlen(name), (void *)&value, sizeof (value));
}

static void
fakebop_setprop_64(char *name, uint64_t value)
{
if (fakebop_prop_debug)
		bop_printf(NULL, "setprop_64: %s->[%lld]\n", name, value);
	fakebop_setprop(name, strlen(name), (void *)&value, sizeof (value));
}

 /*
  * Here we create a bunch of the initial boot properties. This includes what
  * we've been passed in via the command line. It also includes a few values that
  * we compute ourselves.
  *
  * XXX: again largely copied from armv7
  */
 static void
 fakebop_bootprops_init(void)
 {
	int i = 0, proplen = 0, cmdline_len = 0, quote, cont;
 	static int stdout_val = 0;
 	char *c, *prop, *cmdline, *pname;
 	bootinfo_t *bi = &bootinfo;

 	/*
 	 * Set the ramdisk properties for kobj_boot_mountroot() can succeed.
  	 */
	fakebop_setprop_64("ramdisk_start", bi->bi_rdstart);
	fakebop_setprop_64("ramdisk_end", bi->bi_rdend);

 	/*
 	 * Our boot parameters always wil start with kernel /platform/..., but
 	 * the bootloader may in fact stick other properties in front of us. To
 	 * deal with that we go ahead and we include them. We'll find the kernel
 	 * and our properties set via -B when we finally find something without
 	 * an equals sign, mainly kernel.
 	 */
 	c = bi->bi_bootargs;
 	prop = strstr(c, "kernel");
 	if (prop == NULL)
 		bop_panic("failed to find kernel string in boot params!");

	/* Get us past the first kernel string */
 	prop += 6;
 	while (ISSPACE(prop[0]))
 		prop++;
 	proplen = 0;
 	while (prop[proplen] != '\0' && !ISSPACE(prop[proplen]))
 		proplen++;
 	c = prop + proplen + 1;
 	if (proplen > 0) {
 		prop[proplen] = '\0';
 		fakebop_setprop_string("boot-file", prop);
 		/*
 		 * We strip the leading path from whoami so no matter what
 		 * environment we enter into here from it is consistent and
 		 * makes some amount of sense.
 		 */
 		if (strstr(prop, "/platform") != NULL)
 			prop = strstr(prop, "/platform");
 		fakebop_setprop_string("whoami", prop);
 	} else {
 		bop_panic("no kernel string in boot params!");
 	}

 	/*
 	 * At this point we have two different sets of properties. Anything that
 	 * involves -B is a boot property, otherwise it becomes part of the
 	 * kernel command line and must be saved in its own property.
 	 */
 	cmdline = fakebop_alloc(NULL, NULL, strlen(c), BO_ALIGN_DONTCARE);
 	cmdline[0] = '\0';
 	while (*c != '\0') {

 		/*
 		 * Just blindly copy it to the commadline if we don't find it.
 		 */
 		if (c[0] != '-' || c[1] != 'B') {
 			cmdline[cmdline_len++] = *c;
 			cmdline[cmdline_len] = '\0';
 			c++;
 			continue;
 		}

 		/* Get past "-B" */
 		c += 2;
 		while (ISSPACE(*c))
 			c++;

 		/*
 		 * We have a series of comma separated key-value pairs to sift
 		 * through here. The key and value are separated by an equals
 		 * sign. The value may quoted with either a ' or ". Note, white
 		 * space will also end the value (as it indicates that we have
 		 * moved on from the -B argument.
 		 */
 		for (;;) {
 			if (*c == '\0' || ISSPACE(*c))
 				break;
 			prop = strchr(c, '=');
 			if (prop == NULL)
 				break;
 			pname = c;
 			*prop = '\0';
 			prop++;
 			proplen = 0;
 			quote = '\0';
 			for (;;) {
 				if (prop[proplen] == '\0')
 					break;

 				if (proplen == 0 && (prop[0] == '\'' ||
 				    prop[0] == '"')) {
 					quote = prop[0];
 					proplen++;
 					continue;
 				}

 				if (quote != '\0') {
 					if (prop[proplen] == quote)
 						quote = '\0';
 					proplen++;
 					continue;
 				}

 				if (prop[proplen] == ',' ||
 				    ISSPACE(prop[proplen]))
 					break;

 				/* We just have a normal character */
 				proplen++;
 			}

 			/*
 			 * Save whether we should continue or not and update 'c'
 			 * now as we will most likely clobber the string when we
 			 * are done.
 			 */
 			cont = (prop[proplen] == ',');
 			if (prop[proplen] != '\0')
 				c = prop + proplen + 1;
 			else
 				c = prop + proplen;

 			if (proplen == 0) {
 				fakebop_setprop_string(pname, "true");
 			} else {
 				/*
 				 * When we copy the prop, do not include the
 				 * quote.
 				 */
 				if (prop[0] == prop[proplen - 1] &&
 				    (prop[0] == '\'' || prop[0] == '"')) {
 					prop++;
 					proplen -= 2;
 				    }
 				prop[proplen] = '\0';
 				fakebop_setprop_string(pname, prop);
 			}

 			if (cont == 0)
 				break;
 		}
 	}

 	/*
 	 * Yes, we actually set both names here. The latter is set because of
 	 * 1275.
 	 */
 	fakebop_setprop_string("boot-args", cmdline);
 	fakebop_setprop_string("bootargs", cmdline);

	/*
 	 * Here are some things that we make up, just like our i86pc brethren.
 	 */
 	fakebop_setprop_32("stdout", 0);
 	fakebop_setprop_string("mfg-name", "ARMv8 - AARCH64");
 	fakebop_setprop_string("impl-arch-name", "ARMv8 - AARCH64");
 }


static int
fakebop_getproplen(struct bootops *bops, const char * pname)
{
	// bop_panic("NYI: fakebop_getproplen");
	// return (-1);
	bootprop_t *p;

	if (fakebop_prop_debug)
		bop_printf(NULL, "fakebop_getproplen: asked for %s\n", pname);
	for (p = bprops; p != NULL; p = p->bp_next) {
		if (strcmp(pname, p->bp_name) == 0)
			return (p->bp_vlen);
	}
	if (fakebop_prop_debug != 0)
		bop_printf(NULL, "prop %s not found\n", pname);
	return (-1);
}

static int
fakebop_getprop(struct bootops *bops, const char *pname, void *value)
{

	bootprop_t *p;

	if (fakebop_prop_debug)
		bop_printf(NULL, "fakebop_getprop: asked for %s\n", pname);
	for (p = bprops; p != NULL; p = p->bp_next) {
		if (strcmp(pname, p->bp_name) == 0)
			break;
	}
	if (p == NULL) {
		if (fakebop_prop_debug)
			bop_printf(NULL, "fakebop_getprop: ENOPROP %s\n",
			    pname);
		return (-1);
	}
	if (fakebop_prop_debug)
		bop_printf(NULL, "fakebop_getprop: copying %d bytes to 0x%x\n",
		    p->bp_vlen, value);
	bcopy(p->bp_value, value, p->bp_vlen);
	return (0);

	// bop_printf(bops, "fakebop_getprop called with name %s", name);
	// bop_panic("NYI: fakebop_getprop");
	// return (-1);
}


// static int fakebop_alloc_debug = 0;
/*
 * fakebop memory allocations scheme
 *
 * It's a virtual world out there. The loader thankfully tells us all the areas
 * that it has mapped for us and it also tells us about the page table arena --
 * a set of addresses that have already been set aside for us. We have two
 * different kinds of allocations to worry about:
 *
 *    o Those that specify a particular vaddr
 *    o Those that do not specify a particular vaddr
 *
 * Those that do not specify a particular vaddr will come out of our scratch
 * space which is a fixed size arena of 16 MB (FAKEBOP_ALLOC_SIZE) that we set
 * aside at the beginning of the allocator. If we end up running out of that
 * then we'll go ahead and figure out a slightly larger area to worry about.
 *
 * Now, for those that do specify a particular vaddr we'll allocate more
 * physical address space for it. The loader set aside enough L2 page tables for
 * us that we'll go ahead and use the next 4k aligned address.
 */
// #define	FAKEBOP_ALLOC_SIZE	(16 * 1024 * 1024)

// static size_t bop_alloc_scratch_size;
// static uintptr_t bop_alloc_scratch_next;	/* Next scratch address */
// static uintptr_t bop_alloc_scratch_last;	/* Last scratch address */

// static uintptr_t bop_alloc_pnext;		/* Next paddr */
// static uintptr_t bop_alloc_plast;		/* cross this paddr and panic */

// #define	BI_HAS_RAMDISK	0x1

// /*
//  * We need to map and reserve the scratch arena. As a part of this we'll go
//  * through and set up the right place for other paddrs.
//  */
// static void
// fakebop_alloc_init(atag_header_t *chain)
// {
// 	uintptr_t pstart, vstart, pmax;
// 	size_t len;
// 	atag_illumos_mapping_t *aimp;
// 	atag_illumos_status_t *aisp;

// 	aisp = (atag_illumos_status_t *)atag_find(chain, ATAG_ILLUMOS_STATUS);
// 	if (aisp == NULL)
// 		bop_panic("missing ATAG_ILLUMOS_STATUS!\n");
// 	pstart = aisp->ais_freemem + aisp->ais_freeused;
// 	/* Align to next 1 MB boundary */
// 	if (pstart & MMU_PAGEOFFSET1M) {
// 		pstart &= MMU_PAGEMASK1M;
// 		pstart += MMU_PAGESIZE1M;
// 	}
// 	len = FAKEBOP_ALLOC_SIZE;
// 	vstart = pstart;

// 	pmax = 0xffffffff;
// 	/* Make sure the paddrs and vaddrs don't overlap at all */
// 	for (aimp =
// 	    (atag_illumos_mapping_t *)atag_find(chain, ATAG_ILLUMOS_MAPPING);
// 	    aimp != NULL; aimp =
// 	    (atag_illumos_mapping_t *)atag_find(atag_next(&aimp->aim_header),
// 	    ATAG_ILLUMOS_MAPPING)) {
// 		if (aimp->aim_paddr < pstart &&
// 		    aimp->aim_paddr + aimp->aim_vlen > pstart)
// 			bop_panic("phys addresses overlap\n");
// 		if (pstart < aimp->aim_paddr && pstart + len > aimp->aim_paddr)
// 			bop_panic("phys addresses overlap\n");
// 		if (aimp->aim_vaddr < vstart && aimp->aim_vaddr +
// 		    aimp->aim_vlen > vstart)
// 			bop_panic("virt addreses overlap\n");
// 		if (vstart < aimp->aim_vaddr && vstart + len > aimp->aim_vaddr)
// 			bop_panic("virt addresses overlap\n");

// 		if (aimp->aim_paddr > pstart && aimp->aim_paddr < pmax)
// 			pmax = aimp->aim_paddr;
// 	}

// 	armboot_mmu_map(pstart, vstart, len, PF_R | PF_W | PF_X);
// 	bop_alloc_scratch_next = vstart;
// 	bop_alloc_scratch_last = vstart + len;
// 	bop_alloc_scratch_size = len;

// 	bop_alloc_pnext = pstart + len;
// 	bop_alloc_plast = pmax;
// }

// /*
//  * We've been asked to allocate at a specific VA. Allocate the next ragne of
//  * physical addresses and go from there.
//  */
// static caddr_t
// fakebop_alloc_hint(caddr_t virt, size_t size, int align)
// {
// 	uintptr_t start = P2ROUNDUP(bop_alloc_pnext, align);
// 	if (fakebop_alloc_debug != 0)
// 		bop_printf(NULL, "asked to allocate %d bytes at v/p %p/%p\n",
// 		    size, virt, start);
// 	if (start + size > bop_alloc_plast)
// 		bop_panic("fakebop_alloc_hint: No more physical address -_-\n");

// 	armboot_mmu_map(start, (uintptr_t)virt, size, PF_R | PF_W | PF_X);
// 	bop_alloc_pnext = start + size;
// 	return (virt);
// }

// static caddr_t
// fakebop_alloc(struct bootops *bops, caddr_t virthint, size_t size, int align)
// {
// 	caddr_t start;

// 	if (virthint != NULL)
// 		return (fakebop_alloc_hint(virthint, size, align));
// 	if (fakebop_alloc_debug != 0)
// 		bop_printf(bops, "asked to allocate %d bytes\n", size);
// 	if (bop_alloc_scratch_next == 0)
// 		bop_panic("fakebop_alloc_init not called");

// 	if (align == BO_ALIGN_DONTCARE || align == 0)
// 		align = 4;

// 	start = (caddr_t)P2ROUNDUP(bop_alloc_scratch_next, align);
// 	if ((uintptr_t)start + size > bop_alloc_scratch_last)
// 		bop_panic("fakebop_alloc: ran out of scratch space!\n");
// 	if (fakebop_alloc_debug != 0)
// 		bop_printf(bops, "returning address: %p\n", start);
// 	bop_alloc_scratch_next = (uintptr_t)start + size;

// 	return (start);
// }

static void
fakebop_free(struct bootops *bops, caddr_t virt, size_t size)
{
	bop_panic("NYI: fakebop_free");
}


/*
 * XXX: from armv7
 *
 * Nominally this should try and look for bootenv.rc, but seriously, let's not.
 * Instead for now all we're going to to do is look and make sure that console
 * is set. We *should* do something with it, but we're not.
 */
void
boot_prop_finish(void)
{
	// bop_panic("NYI: boot_prop_finish");
	int ret;

	if (fakebop_getproplen(NULL, "console") <= 0)
		bop_panic("console not set");

}

/* XXX: taken straight from arm7/intel */
/*ARGSUSED*/
int
boot_compinfo(int fd, struct compinfo *cbp)
{
	cbp->iscmp = 0;
	cbp->blksize = MAXBSIZE;
	return (0);
}


/* bootconf.h wants bop_printf available (not fakebop_printf) */
#define	BUFFERSIZE 256
static char buffer[BUFFERSIZE];

void
bop_printf(struct bootops *bops, const char *fmt, ...)
{
	if (!have_console) {
		return;
	}
	// bop_panic("NYI: boot_prop_finish");

	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buffer, BUFFERSIZE, fmt, ap);
	va_end(ap);

	bcons_puts(buffer);
}

static void
fakebop_dump_fdt(fdt_header_t *hdr)
{
	DBG_MSG("Dumping Flattened Device Tree");

	if (have_console) {
		bcons_puts("Magic: ");
		fakebop_put_uint32(ntohl(hdr->fdt_magic));
		DBG_MSG(" Should be 0xd00dfeed");

		bcons_puts("Size: ");
		fakebop_put_uint32(ntohl(hdr->fdt_totalsize));
		DBG_MSG(" Should be 0x00010000 for qemu");

		bcons_puts("Struct Off: ");
		fakebop_put_uint32(ntohl(hdr->fdt_off_dt_struct));
		DBG_MSG("");

		bcons_puts("Strings Off: ");
		fakebop_put_uint32(ntohl(hdr->fdt_off_dt_strings));
		DBG_MSG("");

		bcons_puts("Mem Res. Map Off: ");
		fakebop_put_uint32(ntohl(hdr->fdt_off_mem_rsvmap));
		DBG_MSG("");

		bcons_puts("Version: ");
		fakebop_put_uint32(ntohl(hdr->fdt_version));
		DBG_MSG("");

		bcons_puts("Last Comp Version: ");
		fakebop_put_uint32(ntohl(hdr->fdt_last_comp_version));
		DBG_MSG("");

		bcons_puts("CPUID Phys: ");
		fakebop_put_uint32(ntohl(hdr->fdt_boot_cpuid_phys));
		DBG_MSG("");

		bcons_puts("Strings size: ");
		fakebop_put_uint32(ntohl(hdr->fdt_size_dt_strings));
		DBG_MSG("");

		bcons_puts("Struct size: ");
		fakebop_put_uint32(ntohl(hdr->fdt_size_dt_struct));
		DBG_MSG("");
	}



	DBG_MSG("Memory Reservation Info:");
	fdt_reserve_entry_t *iter = (fdt_reserve_entry_t *) fdt_mem_resvmap_addr(hdr);
	while (iter->fdt_address != 0 && iter->fdt_size != 0) {
		bcons_puts("Reserved Addr: ");
		fakebop_put_uint64(ntohll(iter->fdt_address));
		bcons_puts("\tSize: ");
		fakebop_put_uint64(ntohll(iter->fdt_size));
		DBG_MSG("");
		iter = (fdt_reserve_entry_t *) ((uintptr_t) iter +
		    sizeof(fdt_reserve_entry_t));
	}
	DBG_MSG("End Reservation Info.\nDevice Tree Info:");

	uintptr_t token_iter = fdt_struct_addr(hdr);

	int level = 0;
	int j = 0;
	const char *token_name;

	const char *prop_name;

	while (ntohl(*(uint32_t *)token_iter) != FDT_TOKEN_END) {

		uint32_t token = ntohl(*(uint32_t *)token_iter);
		uint32_t prop_len = 0;

		if (have_console) {
			for (j = 0; j < level; j++) {
				bcons_puts("\t");
			}
		}

		switch (token) {
		case FDT_TOKEN_BEGIN_NODE:
			token_iter += sizeof(uint32_t);
			level+=2;
			token_name = (const char *) token_iter;
			bop_printf(NULL,
			    "\tToken begin at addr: 0x%llx, Name: %s\n",
			    token_iter, token_name);
			/*
			 * We need to move the token_iter to the end of the
			 * string + align it to the nearest 4 bytes.
			 */
			while (* (char *)token_iter != '\0') {
				token_iter++;
			}
			/* Pass over the null delimiter too */
			token_iter++;
			while ((uintptr_t)token_iter % 4 != 0) {
				token_iter++;
			}
			break;
		case FDT_TOKEN_END_NODE:
			DBG_MSG("End of node");
			token_iter += sizeof(uint32_t);
			level-=2;
			break;
		case FDT_TOKEN_PROP:
			token_iter += sizeof(uint32_t);
			// bcons_puts("Len of Prop: ");
			prop_len = ntohl(*(uint32_t *)token_iter);
			// fakebop_put_uint32(len);
			// token = ntohl(*(uint32_t *)token_iter);
			bop_printf(NULL, "Len of Prop: %d bytes", prop_len);
			token_iter += sizeof(uint32_t);
			// bcons_puts("\tName: ");
			token = ntohl(*(uint32_t *)token_iter);
			prop_name = (const char *) fdt_string_at_off(hdr, token);
			bop_printf(NULL, "\tName: %s\n", prop_name);
			// DBG_MSG(fdt_string_at_off(hdr, token));

			token_iter += sizeof(uint32_t);
			token = ntohl(*(uint32_t *)token_iter);

			level++;


			//XXX process property
			if (strcmp(token_name, "chosen") == 0) {

					if (have_console) {
						for (j = 0; j < level; j++) {
							bcons_puts("\t");
						}
					}
				if (strcmp(prop_name, "stdout-path") == 0) {

					bootinfo.bi_cmdline = (char *) token_iter;
					bop_printf(NULL, "%s\n",
					    bootinfo.bi_cmdline);
			 	} else if (strcmp(prop_name, "bootargs") == 0) {
					bootinfo.bi_bootargs = (char *) token_iter;
					bop_printf(NULL, "%s\n",
					    bootinfo.bi_bootargs);
			 	} else if (strcmp(prop_name, "linux,initrd-end") == 0) {
			 		bootinfo.bi_rdend = token;
			 		bop_printf(NULL, "0x%x\n",
					    bootinfo.bi_rdend);
			 	} else if (strcmp(prop_name, "linux,initrd-start") == 0) {
			 		bootinfo.bi_rdstart = token;
			 		bop_printf(NULL, "0x%x\n",
					    bootinfo.bi_rdstart);

			 	}
			} else if (strcmp(prop_name, "#size-cells") == 0) {
					if (have_console) {
						for (j = 0; j < level; j++) {
							bcons_puts("\t");
						}
					}
				bop_printf(NULL, "Size Cells: %x\n",
				    token);
			} else if (strcmp(prop_name, "#address-cells") == 0) {
					if (have_console) {
						for (j = 0; j < level; j++) {
							bcons_puts("\t");
						}
					}
				bop_printf(NULL, "Address Cells: %x\n",
				    token);
			} else if (strcmp(token_name, "memory") == 0
			    && strcmp(prop_name, "reg") == 0) {
					if (have_console) {
						for (j = 0; j < level; j++) {
							bcons_puts("\t");
						}
					}
				bootinfo.bi_memstart =
				    ntohll(*(uint64_t *)(token_iter));
				bootinfo.bi_memsize =
				    ntohll(*(uint64_t *)(token_iter + 8));

				bop_printf(NULL, "Mem Start: %llx",
				    bootinfo.bi_memstart);
				bop_printf(NULL, "\tMem Size: %llx\n",
				    bootinfo.bi_memsize);

			} else if (strcmp(prop_name, "compatible") == 0) {
					if (have_console) {
						for (j = 0; j < level; j++) {
							bcons_puts("\t");
						}
					}

				for (j = 0; j < prop_len; j++) {
					bop_printf(NULL, "%s", (char *) token_iter + j);
					j += strlen((char *) token_iter + j) + 1;

				}
				bop_printf(NULL, "\n");
			} else if (strcmp(prop_name, "ranges") == 0
			    && strcmp(token_name, "platform@c000000") == 0) {
					if (have_console) {
						for (j = 0; j < level; j++) {
							bcons_puts("\t");
						}
					}

				uint64_t int1 =
				    ntohll(*(uint64_t *)(token_iter));
				uint64_t int2 =
				    ntohll(*(uint64_t *)(token_iter + 8));

				bop_printf(NULL, "Range 1: %llx",
				    bootinfo.bi_memstart);
				bop_printf(NULL, "\tRange 2: %llx\n",
				    bootinfo.bi_memsize);
			}

			level--;

				token_iter += prop_len;
			while (token_iter % 4 != 0) {
				token_iter++;
			}
			break;
		case FDT_TOKEN_NOP:
			token_iter += sizeof(uint32_t);
			break;
		default:
			if (have_console) {
				bcons_puts("Token broken at addr: ");
				fakebop_put_uint64(token_iter);
				DBG_MSG("");
			}
			bop_panic(":(");
			break;
		}
	}
}

/*
 * Part 2:
 *
 * After booting into _start in locore, we're here, where our goal
 * is to mimic the SPARC boot system then get into KRTLD via _kobj_boot()
 *
 * ram_size, initrd_size, kernel_cmdline, loader_start);
 */
void
_fakebop_start(fdt_header_t *arg1)
{
	bootops_t *bops = &bootop;
	extern void _kobj_boot();

	/*
	 * We don't do anything w the string on qemu anyways...
	 * supposed to be initialized with bi_cmdline.
	 *
	 *
	 * Located in device tree as /chosen/, property std-out
	 *
	 * TODO: Hacky but we call dump_fdt twice.
	 * 	First without the boot console to get bi_cmdline
	 * 	and then with it to actually display info
	 */
	fakebop_dump_fdt(arg1);
	bcons_init(bootinfo.bi_cmdline);
	have_console = 1;

	DBG_MSG("\nWelcome to fakebop -- AARCH64 Edition");

	///XXX: qemu hacks
	// arg1 = (fdt_header_t *) 0x40000000;
	// bootinfo.bi_rdstart = 0x48000000;
	// bootinfo.bi_rdend = 0x48000000 + 0x400000; //4MB

	DBG_MSG("Args we were passed: ");
	fakebop_put_uint64( (uintptr_t) arg1);
	DBG_MSG("");

	fakebop_dump_fdt(arg1);

	DBG_MSG("Setting Bootops");
	bops->bsys_version = BO_VERSION;
	bops->bsys_alloc = fakebop_alloc;
	bops->bsys_free = fakebop_free;
	bops->bsys_getproplen = fakebop_getproplen;
	bops->bsys_getprop = fakebop_getprop;
	bops->bsys_printf = bop_printf;

	bop_printf(bops, "Hello printf: %d, %s", 1337, ":)\n");


	DBG_MSG("Initializing allocator + bootprops");
	fakebop_alloc_init();
	fakebop_bootprops_init();

	DBG_MSG("About to enter _kobj_boot");

	_kobj_boot(&bop_sysp, NULL, bops);

	bop_panic("Should never return from _kobj_boot");
	for (;;)
		;
}

void
_fakebop_locore_start(void)
{
	bop_panic("Made it back to _fakebop_locore_start!");
}