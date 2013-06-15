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
	bootops_t *bops = &bootop;
	atag_header_t *h = tagstart;
	const char *tname;
	uintptr_t val;

	/* XXX We should find the actual command line */
	bcons_init(NULL);

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
	DBG_MSG("\n\rThis is as far as we go...\n\rSpinning forever...");
	for (;;)
		;
}
