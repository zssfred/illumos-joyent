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
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_ATAG_H
#define	_SYS_ATAG_H

/*
 * Describe the purpose of the file here.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#define	ATAG_NONE	0x0
#define	ATAG_CORE	0x54410001
#define	ATAG_MEM	0x54410002
#define	ATAG_VIDEOTEXT  0x54410003
#define	ATAG_RAMDISK    0x54410004
#define	ATAG_INITRD2    0x54420005
#define	ATAG_SERIAL	0x54410006
#define	ATAG_REVISION   0x54410007
#define	ATAG_VIDEOLFB   0x54410008
#define	ATAG_CMDLINE	0x54410009

typedef struct atag_header {
	uint32_t	ah_size;	/* size in 4 byte words */
	uint32_t	ah_tag;
} atag_header_t;

typedef struct atag_core {
	atag_header_t	ac_header;
	uint32_t	ac_flags;
	uint32_t	ac_pagesize;
	uint32_t	ac_rootdev;
} atag_core_t;

typedef struct atag_mem {
	atag_header_t	am_header;
	uint32_t	am_size;
	uint32_t	am_start;
} atag_mem_t;

typedef struct atag_ramdisk {
	atag_header_t	ar_header;
	uint32_t	ar_flags;
	uint32_t	ar_size;
	uint32_t	ar_start;
} atag_ramdisk_t;

typedef struct atag_initrd {
	atag_header_t	ai_header;
	uint32_t	ai_start;
	uint32_t	ai_size;
} atag_initrd_t;

typedef struct atag_serial {
	atag_header_t	as_header;
	uint32_t	as_low;
	uint32_t	as_high;
} atag_serial_t;

typedef struct atag_cmdline {
	atag_header_t	al_header;
	char 		al_cmdline[1];
} atag_cmdline_t;

extern atag_header_t *atag_next(atag_header_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_ATAG_H */
