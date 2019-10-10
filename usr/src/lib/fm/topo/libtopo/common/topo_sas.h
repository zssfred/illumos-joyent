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

#ifndef	_TOPO_SAS_H
#define	_TOPO_SAS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	TOPO_VTX_EXPANDER	"expander"
#define	TOPO_VTX_INITIATOR	"initiator"
#define	TOPO_VTX_PORT		"port"
#define	TOPO_VTX_TARGET		"target"

#define	TOPO_PGROUP_EXPANDER		"expander-properties"
#define	TOPO_PROP_EXPANDER_DEVFSNAME	"devfs-name"

#define	TOPO_PGROUP_INITIATOR		"initiator-properties"
#define	TOPO_PROP_INITIATOR_DEVFSNAME	"devfs-name"
#define	TOPO_PROP_INITIATOR_MANUF	"manufacturer"
#define	TOPO_PROP_INITIATOR_MODEL	"model"
#define	TOPO_PROP_INITIATOR_SERIAL	"serial"
#define	TOPO_PROP_INITIATOR_FMRI	"hc-fmri"
#define	TOPO_PROP_INITIATOR_LABEL	"label"

#define	TOPO_PGROUP_SASPORT		"port-properties"
#define	TOPO_PROP_SASPORT_LOCAL_ADDR	"local-sas-address"
#define	TOPO_PROP_SASPORT_ATTACH_ADDR	"attached-sas-address"
/* XXX - add props to capture link error counters per PHY */

#define	TOPO_PGROUP_TARGET		"target-properties"
#define	TOPO_PROP_TARGET_MANUF		"manufacturer"
#define	TOPO_PROP_TARGET_MODEL		"model"
#define	TOPO_PROP_TARGET_SERIAL		"serial"
#define	TOPO_PROP_TARGET_FMRI		"hc-fmri"
#define	TOPO_PROP_TARGET_LABEL		"label"

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_SAS_H */
