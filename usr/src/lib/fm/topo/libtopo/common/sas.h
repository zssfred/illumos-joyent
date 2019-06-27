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
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_SAS_H
#define	_SAS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	SAS_VERSION	1

extern int sas_init(topo_mod_t *, topo_version_t);
extern void sas_fini(topo_mod_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SAS_H */
