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

#ifndef	_FM_SAS_H
#define	_FM_SAS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	SAS_VERSION	1

extern int sas_init(topo_mod_t *, topo_version_t);
extern void sas_fini(topo_mod_t *);

#define	TOPO_METH_SAS2DEV		"sas_dev_fmri"
#define	TOPO_METH_SAS2DEV_DESC		"compute dev-scheme FMRI"
#define	TOPO_METH_SAS2DEV_VERSION	0

#define	TOPO_METH_SAS2HC		"sas_hc_fmri"
#define	TOPO_METH_SAS2HC_DESC		"compute hc-scheme FMRI"
#define	TOPO_METH_SAS2HC_VERSION	0

#define	TOPO_METH_SAS_DEV_PROP		"sas_device_props_set"
#define	TOPO_METH_SAS_DEV_PROP_DESC	"retrieve device properties"
#define	TOPO_METH_SAS_DEV_PROP_VERSION	0

#define	TOPO_METH_SAS_PHY_ERR		"sas_get_phy_err_counter"
#define	TOPO_METH_SAS_PHY_ERR_DESC	"get PHY link state error counters"
#define	TOPO_METH_SAS_PHY_ERR_VERSION	0

#ifdef	__cplusplus
}
#endif

#endif	/* _FM_SAS_H */
