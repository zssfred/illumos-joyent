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
 * Just like in i86pc, we too get the joys of mimicking the SPARC boot system.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/bootconf.h>
#include <sys/boot_console.h>
#include <sys/atag.h>

static bootops_t bootop;
static uint_t kbm_debug = 1;
#define	DBG_MSG(x)	{ if (kbm_debug) bcons_puts(x); bcons_puts("\n\r"); }
#define	BUFFERSIZE	256
static char buffer[BUFFERSIZE];

/*
 * TODO Generalize this
 * This is the set of information tha we want to gather from the various atag
 * headers. This is simple and naive and will need to evolve as we have
 * additional boards beyond just the RPi.
 */
typedef struct bootinfo {
	uint32_t	bi_memsize;
	uint32_t	bi_memstart;
	char 		*bi_cmdline;
} bootinfo_t;

static bootinfo_t bootinfo;	/* Simple set of boot information */

/*
 * XXX This is just a hack to let us see a bit more about what's going on.
 * Normally we'd use vsnprintf, but that includes sys/systm.h which requires
 * almost every header platform header in the world. Also, we're using hex,
 * because hex is cool. Actually, we're really using it because it means we can
 * bitshift instead of divide. There is no integer division in ARMv6 natively.
 * Oops.
 */
static char *
fakebop_hack_ultostr(unsigned long value, char *ptr)
{
	ulong_t t, val = (ulong_t)value;
	char c;

	do {
		c = (char)('0' + val - 16 * (t = (val >> 4)));
		if (c > '9')
			c += 'A' - '9' - 1;
		*--ptr = c;
	} while ((val = t) != 0);

	*--ptr = 'x';
	*--ptr = '0';

	return (ptr);
}

static void
fakebop_dump_tags(void *tagstart)
{
	atag_header_t *h = tagstart;
	atag_core_t *acp;
	atag_mem_t *amp;
	atag_cmdline_t *alp;
	uintptr_t val;
	const char *tname;
	int i;
	char *c;

	DBG_MSG("starting point:");
	DBG_MSG(fakebop_hack_ultostr((uintptr_t)h, &buffer[BUFFERSIZE-1]));
	DBG_MSG("first atag size:");
	DBG_MSG(fakebop_hack_ultostr(h->ah_size, &buffer[BUFFERSIZE-1]));
	DBG_MSG("first atag tag:");
	DBG_MSG(fakebop_hack_ultostr(h->ah_tag, &buffer[BUFFERSIZE-1]));
	while (h != NULL) {
		switch (h->ah_tag) {
		case ATAG_CORE:
			tname = "ATAG_CORE";
			break;
		case ATAG_MEM:
			tname = "ATAG_MEM";
			break;
		case ATAG_VIDEOTEXT:
			tname = "ATAG_VIDEOTEXT";
			break;
		case ATAG_RAMDISK:
			tname = "ATAG_RAMDISK";
			break;
		case ATAG_INITRD2:
			tname = "ATAG_INITRD2";
			break;
		case ATAG_SERIAL:
			tname = "ATAG_SERIAL";
			break;
		case ATAG_REVISION:
			tname = "ATAG_REVISION";
			break;
		case ATAG_VIDEOLFB:
			tname = "ATAG_VIDEOLFB";
			break;
		case ATAG_CMDLINE:
			tname = "ATAG_CMDLINE";
			break;
		default:
			tname = fakebop_hack_ultostr(h->ah_tag,
			    &buffer[BUFFERSIZE-1]);
			break;
		}
		DBG_MSG("tag:");
		DBG_MSG(tname);
		DBG_MSG("size:");
		DBG_MSG(fakebop_hack_ultostr(h->ah_size,
		    &buffer[BUFFERSIZE-1]));
		/* Extended information */
		switch (h->ah_tag) {
		case ATAG_CORE:
			if (h->ah_size == 2) {
				DBG_MSG("ATAG_CORE has no extra information");
			} else {
				acp = (atag_core_t *)h;
				DBG_MSG("\tflags:");
				bcons_puts("\t");
				DBG_MSG(fakebop_hack_ultostr(acp->ac_flags,
				    &buffer[BUFFERSIZE-1]));
				DBG_MSG("\tpage:");
				bcons_puts("\t");
				DBG_MSG(fakebop_hack_ultostr(acp->ac_pagesize,
				    &buffer[BUFFERSIZE-1]));
				DBG_MSG("\troot:");
				bcons_puts("\t");
				DBG_MSG(fakebop_hack_ultostr(acp->ac_rootdev,
				    &buffer[BUFFERSIZE-1]));
			}
			break;
		case ATAG_MEM:
			amp = (atag_mem_t *)h;
			DBG_MSG("\tsize:");
			bcons_puts("\t");
			DBG_MSG(fakebop_hack_ultostr(amp->am_size,
			    &buffer[BUFFERSIZE-1]));
			DBG_MSG("\tstart:");
			bcons_puts("\t");
			DBG_MSG(fakebop_hack_ultostr(amp->am_start,
			    &buffer[BUFFERSIZE-1]));
			break;
		case ATAG_CMDLINE:
			alp = (atag_cmdline_t *)h;
			DBG_MSG("\tcmdline:");
			/*
			 * We have no intelligent thing to wrap our tty at 80
			 * chars so we just do this a bit more manually for now.
			 */
			i = 0;
			c = alp->al_cmdline;
			while (*c != '\0') {
				bcons_putchar(*c++);
				if (++i == 72) {
					bcons_puts("\n\r");
					i = 0;
				}
			}
			bcons_puts("\n\r");
			break;
		default:
			break;
		}
		h = atag_next(h);
	}
}

static void
fakebop_getatags(void *tagstart)
{
	atag_mem_t *amp;
	atag_cmdline_t *alp;
	atag_header_t *ahp = tagstart;
	bootinfo_t *bp = &bootinfo;

	while (ahp != NULL) {
		switch (ahp->ah_tag) {
		case ATAG_MEM:
			amp = (atag_mem_t *)ahp;
			bp->bi_memsize = amp->am_size;
			bp->bi_memstart = amp->am_start;
			break;
		case ATAG_CMDLINE:
			alp = (atag_cmdline_t *)ahp;
			bp->bi_cmdline = alp->al_cmdline;
		default:
			break;
		}
		ahp = atag_next(ahp);
	}
}

void
bop_panic(const char *msg)
{
	bcons_puts("ARM bop_panic: ");
	DBG_MSG(msg);
	DBG_MSG("Spinning forever...");
	for (;;)
		;
}

static caddr_t
fakebop_alloc(struct bootops *bops, caddr_t virthint, size_t size, int align)
{
	bop_panic("Called into fakebop_alloc");
	return (NULL);
}

static void
fakebop_free(struct bootops *bops, caddr_t virt, size_t size)
{
	bop_panic("Called into fakebop_free");
}

static int
fakebop_getproplen(struct bootops *bops, const char *prop)
{
	bop_panic("Called into fakebop_getproplen");
	return (-1);
}

static int
fakebop_getprop(struct bootops *bops, const char *prop, void *value)
{
	bop_panic("Called into fakebop_getprop");
	return (-1);
}

static void
fakebop_printf(bootops_t *bop, const char *fmt, ...)
{
	bop_panic("Called into fakebop_printf");
}

void
boot_prop_finish(void)
{
	bop_panic("Called into boot_prop_finish");
}

/*
 * Welcome to the kernel. We need to make a fake version of the boot_ops and the
 * boot_syscalls and then jump our way to _kobj_boot(). Here, we're borrowing
 * the Linux bootloader expectations, mostly because a lot of bootloaders and
 * boards already do this. If it turns out that we want to abstract this in the
 * future, then we should have locore.s do that before we get here.
 */
void
_fakebop_start(void *zeros, uint32_t machid, void *tagstart)
{
	bootinfo_t *bip = &bootinfo;
	bootops_t *bops = &bootop;
	atag_header_t *h = tagstart;
	const char *tname;
	uintptr_t val;

	fakebop_getatags(tagstart);
	bcons_init(bip->bi_cmdline);

	DBG_MSG("Welcome to fakebop -- ARM edition");
	/*
	 * XXX For now, we explicitly put a gating getc into place. This gives
	 * us enough time to ensure that anyone who is using the serial console
	 * is in a place where they can see output.
	 */
	(void) bcons_getchar();
	DBG_MSG("Welcome to fakebop -- ARM edition");
	buffer[BUFFERSIZE-1] = '\0';
	DBG_MSG("boot machid:");
	DBG_MSG(fakebop_hack_ultostr((uintptr_t)machid, &buffer[BUFFERSIZE-1]));
	DBG_MSG("boot atag location:");
	DBG_MSG(fakebop_hack_ultostr((uintptr_t)tagstart,
	    &buffer[BUFFERSIZE-1]));
	(void) bcons_getchar();
	fakebop_dump_tags(tagstart);

	/*
	 * Fill in the bootops vector
	 */
	bops->bsys_version = BO_VERSION;
	bops->bsys_alloc = fakebop_alloc;
	bops->bsys_free = fakebop_free;
	bops->bsys_getproplen = fakebop_getproplen;
	bops->bsys_getprop = fakebop_getprop;
	bops->bsys_printf = fakebop_printf;

	bop_panic("This is as far as we go...");
}
