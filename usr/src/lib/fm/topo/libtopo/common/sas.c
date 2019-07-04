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

/*
 * The sas FMRI scheme is intended to be used in conjuction with a
 * digraph-based topology to represent a SAS fabric.
 *
 * There are four types of vertices in the topology:
 *
 * initiator
 * ---------
 * An initiator is a device on the SAS fabric that originates SCSI commands.
 * Typically this is a SAS host-bus adapter (HBA) which can be built onto the
 * system board or be part of a PCIe add-in card.
 *
 * XXX - add description of initiator node properties
 *
 * port
 * ----
 * A port is a logical construct that represents a grouping of one or more
 * PHYs.  A port with one PHY is known as a narrow port.  An example of a
 * narrow port would be the connection from an expander to a target device.
 * A port with more than one PHY is known as a wide port.  A typical example
 * of a wide port would be the connection from an initiator to an exander
 * (typically 4 or 8 PHYs wide).
 *
 * XXX - add description of port node properties
 *
 * target
 * ------
 * A target (or end-device) represents the device that is receiving
 * SCSI commands from the an initiator.   Examples include disks and SSDs as
 * well as SMP and SES management devices.  SES and SMP targets would
 * be connected to an expander.  Disk/SSD targets can be connected to an
 * expander or directly attached (via a narrow port) to an initiator.
 *
 * XXX - add description of target node properties
 *
 * XXX - It'd be really cool if we could check for a ZFS pool config and
 * try to match the target to a leaf vdev and include the zfs-scheme FMRI of
 * that vdev as a property on this node.
 *
 * XXX - Similarly, for disks/ssd's it'd be cool if we could a match the
 * target to a disk node in the hc-scheme topology and also add the
 * hc-scheme FMRI of that disk as a property on this node.  This one would
 * have to be a dynamic (propmethod) property because we'd need to walk
 * the hc-schem tree, which may not have been built when we're enumerating.
 *
 * expander
 * --------
 * An expander acts as both a port multiplexer and expander routing signals
 * between one or more initiators and one or more targets or possibly a
 * second layer of downstream expanders, depending on the size of the fabric.
 * The SAS specification optionally allows for up to two levels of expanders
 * between the initiator(s) and target(s).
 *
 * XXX - add description of expander node properties
 *
 * sas scheme FMRIs
 * ----------------
 * The resource in the sas FMRI scheme doesn't represent a discrete component
 * like the hc or svc schemes.  Rather, the resource represents a unique
 * path from a given initiator to a given target.  Hence, the first two
 * node/instance pairs are always an initiator and port and last two pairs
 * are always a port and a target. In between there may be one or two sets
 * of expander and port pairs.
 *
 * e.g.
 * sas:///initiator=<inst>/<port>=<inst>/.../port=<inst>/target=<inst>
 *
 * Node instance numbers are based on the local SAS address of the underlying
 * component.  Each initiator, expander and target will have a unique[1] SAS
 * address.  And each port from an initiator or to a target will also have a
 * unique SAS address.  However, expander ports are not individually
 * addressed.  If the expander port is attached, the instance number shall
 * be the SAS address of the attached device.  If the expander port is not
 * attached, the instance number shall be the SAS address of the expander,
 * itself.
 *
 * [1] The SAS address will be unique within a given SAS fabric (domain)
 *
 * The nvlist representation of the FMRI consists of a single nvpair (sas-path)
 * which is an array of nvlists where each nvlist contains the following
 * nvpairs:
 *
 * name             type                   value
 * ----             ----                   -----
 * sas-name         DATA_TYPE_STRING       (initiator|port|expander|target)
 * sas-id           DATA_TYPE_UINT64       SAS address (see above)
 */
#include <libnvpair.h>
#include <fm/topo_mod.h>

#include <sys/fm/protocol.h>
#include <sys/types.h>

#include <topo_digraph.h>
#include <topo_sas.h>
#include <topo_method.h>
#include <topo_subr.h>
#include "sas.h"

static int sas_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_fmri_create(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t sas_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_str2nvl },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_create },
	{ NULL }
};

static int sas_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void sas_release(topo_mod_t *, tnode_t *);

static const topo_modops_t sas_ops =
	{ sas_enum, sas_release };

static const topo_modinfo_t sas_info =
	{ "sas", FM_FMRI_SCHEME_SAS, SAS_VERSION, &sas_ops };

int
sas_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOSASDEBUG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing sas builtin\n");

	if (version != SAS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &sas_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register sas_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1);
	}

	return (0);
}

void
sas_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

/*ARGSUSED*/
static int
sas_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	/*
	 * XXX - this code simply hardcodes a minimal topology in order to
	 * facilitate early unit testing of the topo_digraph code.  This
	 * will be replaced by proper code that will discover and dynamically
	 * enumerate the SAS fabric(s).
	 */
	topo_vertex_t *ini, *ini_p1, *exp_in1, *exp, *exp_out1, *exp_out2,
	    *tgt1_p1, *tgt2_p1, *tgt1, *tgt2;
	uint64_t ini_addr = 0x5003048023567a00;
	uint64_t exp_addr = 0x500304801861347f;
	uint64_t tg1_addr = 0x5000cca2531b1025;
	uint64_t tg2_addr = 0x5000cca2531a41b9;

	/* (void) topo_method_register(mod, pnode, sas_methods); */
	if ((ini = topo_vertex_new(mod, TOPO_VTX_INITIATOR, ini_addr)) == NULL)
		return (-1);
	if ((ini_p1 = topo_vertex_new(mod, TOPO_VTX_PORT, ini_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, ini, ini_p1) != 0)
		return (-1);

	if ((exp_in1 = topo_vertex_new(mod, TOPO_VTX_PORT, ini_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, ini_p1, exp_in1) != 0)
		return (-1);

	if ((exp = topo_vertex_new(mod, TOPO_VTX_EXPANDER, exp_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, exp_in1, exp) != 0)
		return (-1);

	if ((exp_out1 = topo_vertex_new(mod, TOPO_VTX_PORT, tg1_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, exp, exp_out1) != 0)
		return (-1);

	if ((tgt1_p1 = topo_vertex_new(mod, TOPO_VTX_PORT, tg1_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, exp_out1, tgt1_p1) != 0)
		return (-1);

	if ((tgt1 = topo_vertex_new(mod, TOPO_VTX_TARGET, tg1_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, tgt1_p1, tgt1) != 0)
		return (-1);

	if ((exp_out2 = topo_vertex_new(mod, TOPO_VTX_PORT, tg2_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, exp, exp_out2) != 0)
		return (-1);

	if ((tgt2_p1 = topo_vertex_new(mod, TOPO_VTX_PORT, tg2_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, exp_out2, tgt2_p1) != 0)
		return (-1);

	if ((tgt2 = topo_vertex_new(mod, TOPO_VTX_TARGET, tg2_addr)) == NULL)
		return (-1);
	if (topo_edge_new(mod, tgt2_p1, tgt2) != 0)
		return (-1);

	return (0);
}

static void
sas_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

/*
 * XXX still need to implement the three methods below
 */

/*ARGSUSED*/
static int
sas_fmri_create(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	return (0);
}

/*ARGSUSED*/
static int
sas_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	uint8_t scheme_version;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &scheme_version) != 0 ||
	    scheme_version > FM_SAS_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	return (0);
}

/*ARGSUSED*/
static int
sas_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	uint8_t scheme_version;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &scheme_version) != 0 ||
	    scheme_version > FM_SAS_SCHEME_VERSION)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	return (0);
}
