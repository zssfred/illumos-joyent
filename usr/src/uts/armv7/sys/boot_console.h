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

#ifndef _BOOT_CONSOLE_H
#define	_BOOT_CONSOLE_H

/*
 * As we do not yet have a formal PSM definition for every different ARM board
 * that might exist, this is forming the temporary interface which we'll use for
 * having fakebop be able to deal with the console.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize the boot console. The argument is a string passed in from the
 * bootloader that may be consulted to determine which of many potential
 * consoles we should initialize.
 */
extern void bcons_init(char *);

/*
 * Put one character onto the boot console.
 */
extern void bcons_putchar(int);

/*
 * Put a null terminated string onto the boot console.
 */
extern void bcons_puts(const char *);

/*
 * Grab one character from the boot console.
 */
extern int bcons_getchar(void);

/*
 * Is there a character ready to read from the console.
 */
extern int bcons_ischar(void);

#ifdef __cplusplus
}
#endif

#endif /* _BOOT_CONSOLE_H */
