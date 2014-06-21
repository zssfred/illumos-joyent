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

#ifndef _SYS_OVERLAY_PROP_H
#define	_SYS_OVERLAY_PROP_H

/*
 * Overlay device sub-system property interfaces
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum overlay_prop_type {
	OVERLAY_PROP_T_INT = 0x1,	/* signed int */
	OVERLAY_PROP_T_UINT,		/* unsigned int */
	OVERLAY_PROP_T_IP,		/* sinaddr6 */
	OVERLAY_PROP_T_STRING		/* OVERLAY_PROPS_SIZEMAX */
} overlay_prop_type_t;

typedef struct overlay_prop {
	const char *ovpr_name;
	overlay_prop_type_t ovpr_type;
	void *ovpr_val;
	ssize_t ovpr_size;
	void *ovpr_default;
	ssize_t ovpr_defsize;
} overlay_prop_t;

#define	OVERLAY_TBL_NPROPS(x)	(sizeof (x) / sizeof (overlay_prop_t))
#define	OVERLAY_PROP_NAMELEN	64
#define	OVERLAY_PROP_SIZEMAX	256

#ifdef __cplusplus
}
#endif

#endif /* _SYS_OVERLAY_PROP_H */
