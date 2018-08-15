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

static bootops_t bootop;

static struct boot_syscalls bop_sysp = {
	bcons_getchar,
	bcons_putchar,
	bcons_ischar,
};

/*
 * Debugging macros
 */
static uint_t kbm_debug = 1;
#define	DBG_MSG(s)	{ if (kbm_debug) { bcons_puts(s); bcons_puts("\n"); } }

/* XXX: Thse are terrible. */
static void
fakebop_put_uint64(uint64_t in)
{
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

static caddr_t
fakebop_alloc(struct bootops *bops, caddr_t virthint, size_t size, int align)
{
	bop_panic("NYI: fakebop_alloc");
	return (NULL);
}

static void
fakebop_free(struct bootops *bops, caddr_t virt, size_t size)
{
	bop_panic("NYI: fakebop_free");
}

static int
fakebop_getproplen(struct bootops *bops, const char * name)
{
	bop_panic("NYI: fakebop_getproplen");
	return (-1);
}

static int
fakebop_getprop(struct bootops *bops, const char *name, void *buf)
{
	bop_panic("NYI: fakebop_getprop");
	return (-1);
}

/* bootconf.h wants bop_printf available (not fakebop_printf) */
#define	BUFFERSIZE 256
static char buffer[BUFFERSIZE];

void
bop_printf(struct bootops *bops, const char *fmt, ...)
{
	// bop_panic("NYI: boot_prop_finish");

	va_list ap;

	va_start(ap, fmt);
	(void) vsnprintf(buffer, BUFFERSIZE, fmt, ap);
	va_end(ap);

	bcons_puts(buffer);
}

void
boot_prop_finish(void)
{
	bop_panic("NYI: boot_prop_finish");
}

static void
fakebop_dump_fdt(fdt_header_t *hdr)
{
	DBG_MSG("Dumping Flattened Device Tree");

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

	while (ntohl(*(uint32_t *)token_iter) != FDT_TOKEN_END) {

		uint32_t token = ntohl(*(uint32_t *)token_iter);
		uint32_t len = 0;
		for (j = 0; j < level; j++) {
			bcons_puts("\t");
		}

		switch (token) {
		case FDT_TOKEN_BEGIN_NODE:
			token_iter += sizeof(uint32_t);
			len = 0;

			level+=2;
			bcons_puts("\tToken begin at addr: ");
			fakebop_put_uint64(token_iter);
			bcons_puts(" Name: ");
			DBG_MSG((const char *) token_iter);
			while (* (char *)token_iter != '\0') {
				token_iter++;
				len++;
			}
			while ((uintptr_t)token_iter % 4 != 0) {
				token_iter++;
			}
			if ((len % 4) == 0) {
				token_iter += sizeof(uint32_t);
			}
			break;
		case FDT_TOKEN_END_NODE:
			DBG_MSG("End of node");
			token_iter += sizeof(uint32_t);
			level-=2;
			break;
		case FDT_TOKEN_PROP:
			token_iter += sizeof(uint32_t);
			bcons_puts("Len of Prop: ");
			len = ntohl(*(uint32_t *)token_iter);
			fakebop_put_uint32(len);
			token_iter += sizeof(uint32_t);
			bcons_puts("\tName: ");
			token = ntohl(*(uint32_t *)token_iter);
			DBG_MSG(fdt_string_at_off(hdr, token));

			token_iter += sizeof(uint32_t);
			//XXX process property
				token_iter += len;
			while (token_iter % 4 != 0) {
				token_iter++;
			}
			break;
		case FDT_TOKEN_NOP:
			token_iter += sizeof(uint32_t);
			break;
		default:
			bcons_puts("Token broken at addr: ");
			fakebop_put_uint64(token_iter);
			DBG_MSG("");
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
	 */
	bcons_init(NULL);

	DBG_MSG("\nWelcome to fakebop -- AARCH64 Edition");

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

	DBG_MSG("About to enter _kobj_boot");

	_kobj_boot(&bop_sysp, NULL, bops);

	bop_panic("Should never return from _kobj_boot");
	for (;;)
		;
}

void
_fakebop_locore_start(struct boot_syscalls *sysp, struct bootops *bops)
{
	bop_panic("Made it back to _fakebop_locore_start!");
}