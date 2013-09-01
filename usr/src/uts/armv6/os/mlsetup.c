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

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/privregs.h>
#include <sys/cpuvar.h>
#include <sys/stack.h>
#include <sys/vmparam.h>

#include <sys/bootconf.h>

/*
 * We've been given the name of the kernel. From this we should construct the
 * module path.
 *
 * XXX At this time we aren't really handlin the fact that the there are
 * different machine implementations on ARMv6. When we do we need to come back
 * and revisit this and make sure that we properly set impl-arch-name. That
 * means that for now we basically want to return /platform/armv6/kernel for
 * now. Eventually this will become /platform/<mumble>/kernel
 * /platform/armv6/kernel. See uts/sun4/os/mlsetup.c for an example.
 */
void
mach_modpath(char *path, const char *filename)
{
	char *p;

	if ((p = strrchr(filename, '/')) == NULL)
		return;

	while (p > filename && *(p - 1) == '/')
		p--;	/* remove trailing '/' characters */
	if (p == filename)
		p++;	/* so "/" -is- the modpath in this case */

	/*
	 * If we ever support AARCH64 in this file, we must go through and
	 * remove its suffix from the file name if it is there.
	 */
	(void) strncpy(path, filename, p - filename);
}

extern void *romp;
extern struct bootops *ops;
extern struct bootops *bootops;
extern struct boot_syscalls *sysp;

void
mlsetup(struct regs *rp)
{
	bop_panic("mlsetup!");
}
