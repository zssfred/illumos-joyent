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
 * Copyright 2013 (c) Joyent, Inc.  All rights reserved.
 */

/*
 * Bootstrap krtld.
 */

#include <sys/types.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/auxv.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>

/*
 * Kernel's current entry point.
 */
extern void _locore_start();

/*
 * This is the bridge that gets us between the initial kernel and into
 * kobj_init. It is responsible for setting up the aux vector that we need to
 * pass in.
 */

/*ARGSUSED3*/
void
_kobj_boot(struct boot_syscalls *bsysp, void *dvec, struct bootops *bops)
{
	val_t auxv[BA_NUM];
	int i;

	for (i = 0; i < BA_NUM; i++)
		auxv[i].ba_val = NULL;

	auxv[BA_ENTRY].ba_ptr = _locore_start;
	auxv[BA_IFLUSH].ba_val = 1;
	/*
	 * XXX Currently PAGESIZE is being defined to _pagesize which isn't the
	 * case here on other platforms. For now we manually set the size to 4k.
	 */
	auxv[BA_PAGESZ].ba_val = 0x1000;

	kobj_init(bsysp, dvec, bops, auxv);
}
