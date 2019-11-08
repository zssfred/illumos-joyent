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
 *   initiator properties
 *   --------------------
 *   Initiator nodes are populated with the following public properties.
 *   - manufacturer
 *   - model name
 *   - devfs name
 *   - hc fmri
 *   - XXX TODO: serial number
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
 *   target properties
 *   -----------------
 *   Target nodes are populated with the following public properties.
 *   - manufacturer
 *   - model name
 *   - serial number
 *   - hc fmri
 *
 * XXX - It'd be really cool if we could check for a ZFS pool config and
 * try to match the target to a leaf vdev and include the zfs-scheme FMRI of
 * that vdev as a property on this node.
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
 * Version 0 sas FMRI scheme
 * -------------------------
 * Two types of resources can be represented in the sas FMRI scheme: paths
 * and pathnodes.  The "type" field in the authority portion of the FMRI
 * denotes whether the FMRI indentifies a pathnode or path:
 *
 * e.g.
 * sas://type=path/....
 * sas://type=pathnode/....
 *
 * Path
 * ----
 * The first resource type is a path, which represents a unique path from a
 * given initiator to a given target.  Hence, the first two node/instance pairs
 * are always an initiator and port and the last two pairs are always a port
 * and a target. In between there may be one or two sets of expander and port
 * pairs.
 *
 * e.g.
 * sas://<auth>/initiator=<inst>/<port>=<inst>/.../port=<inst>/target=<inst>
 *
 * Node instance numbers are based on the local SAS address of the underlying
 * component.  Each initiator, expander and target will have a unique[1] SAS
 * address.  And each port from an initiator or to a target will also have a
 * unique SAS address.  Note that expander ports are not individually
 * addressed, thus the instance number shall be the SAS address of the
 * expander, itself.
 *
 * [1] The SAS address will be unique within a given SAS fabric (domain)
 *
 * The nvlist representation of the FMRI consists of two nvpairs:
 *
 * name               type                   value
 * ----               ----                   -----
 * sas-fmri-version   DATA_TYPE_UINT8        0
 * sas-path           DATA_TYPE_NVLIST_ARRAY see below
 *
 * sas-path is an array of nvlists where each nvlist contains the following
 * nvpairs:
 *
 * name               type                   value
 * ----               ----                   -----
 * sas-name           DATA_TYPE_STRING       (initiator|port|expander|target)
 * sas-id             DATA_TYPE_UINT64       SAS address (see above)
 *
 *
 * Pathnode
 * --------
 * The second resource type in the sas FMRI scheme is a pathnode, which
 * represents a single node in the underlying graph topology.  In this form,
 * the FMRI consists of a single sas-name/sas-id pair.  In order to
 * differentiate the FMRIs for expander "port" nodes, which will share the same
 * SAS address as the expander, the range of PHYs associated with the port will
 * be added to the authority portion of the FMRI.  For expander ports that
 * connect directly to a target device, this will be a narrow port that spans a
 * single PHY:
 *
 * e.g.
 *
 * sas://type=pathnode:start-phy=0:end-phy=0/port=500304801861347f
 * sas://type=pathnode:start-phy=1:end-phy=1/port=500304801861347f
 *
 * For expander ports that connect to another expander, this will be a wide
 * port that will span a range of phys (typically 4 or 8 wide)
 *
 * e.g.
 *
 * sas://type=pathnode:start_phy=0:end_phy=7/port=500304801861347f
 *
 * Overview of SAS Topology Generation
 * -----------------------------------
 * The SAS topology is iterated using this high-level logic:
 *
 * 1) Each HBA is discovered.
 * 2) Each SAS port on each HBA is added to a list of ports that need to be
 *    further discovered (search_list).
 * 3) Create a digraph vertex for every device discovered. Some information is
 *    stored with each vertex like its local WWN, attached WWN, and port
 *    attributes.
 * 4) Iterate through each vertex drawing edges between all connected
 *    vertices. The connections are determined by matching local/attached WWN
 *    pairs. E.g. a disk with an attached WWN of 0xDEADBEEF and an HBA with a
 *    local WWN of 0xDEADBEEF are connected.
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

#include <smhbaapi.h>
#include <scsi/libsmp.h>
#include <sys/libdevid.h> /* for scsi_wwnstr_to_wwn */

#include <libdevinfo.h>

/* Methods for the root sas topo node. */
static int sas_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_fmri_create(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

/* Methods for child sas topo nodes. */
static int sas_dev_fmri(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_hc_fmri(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_device_props_set(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int sas_get_phy_err_counter(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t sas_root_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_str2nvl },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_fmri_create },
	{ NULL }
};

static const topo_method_t sas_initiator_methods[] = {
	{ TOPO_METH_SAS2DEV, TOPO_METH_SAS2DEV_DESC, TOPO_METH_SAS2DEV_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_dev_fmri },
	{ TOPO_METH_SAS2HC, TOPO_METH_SAS2HC_DESC, TOPO_METH_SAS2HC_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_hc_fmri },
	{ TOPO_METH_SAS_DEV_PROP, TOPO_METH_SAS_DEV_PROP_DESC,
	    TOPO_METH_SAS_DEV_PROP_VERSION, TOPO_STABILITY_INTERNAL,
	    sas_device_props_set },
	{ NULL }
};

static const topo_method_t sas_expander_methods[] = {
	{ TOPO_METH_SAS2DEV, TOPO_METH_SAS2DEV_DESC, TOPO_METH_SAS2DEV_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_dev_fmri },
	{ NULL }
};

static const topo_method_t sas_target_methods[] = {
	{ TOPO_METH_SAS2DEV, TOPO_METH_SAS2DEV_DESC, TOPO_METH_SAS2DEV_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_dev_fmri },
	{ TOPO_METH_SAS2HC, TOPO_METH_SAS2HC_DESC, TOPO_METH_SAS2HC_VERSION,
	    TOPO_STABILITY_INTERNAL, sas_hc_fmri },
	{ TOPO_METH_SAS_DEV_PROP, TOPO_METH_SAS_DEV_PROP_DESC,
	    TOPO_METH_SAS_DEV_PROP_VERSION, TOPO_STABILITY_INTERNAL,
	    sas_device_props_set },
	{ NULL }
};

static const topo_method_t sas_port_methods[] = {
	{ TOPO_METH_SAS_PHY_ERR, TOPO_METH_SAS_PHY_ERR_DESC,
	    TOPO_METH_SAS_PHY_ERR_VERSION, TOPO_STABILITY_INTERNAL,
	    sas_get_phy_err_counter },
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
	HBA_STATUS ret;

	if (getenv("TOPOSASDEBUG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing sas builtin\n");

	if (version != SAS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if ((ret = HBA_LoadLibrary()) != HBA_STATUS_OK) {
		topo_mod_dprintf(mod, "failed to load HBA library (ret=%u)",
		    ret);
		return (-1);
	}

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
	(void) HBA_FreeLibrary();
}

static topo_pgroup_info_t protocol_pgroup = {
	TOPO_PGROUP_PROTOCOL,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

struct sas_phy_info {
	uint32_t	start_phy;
	uint32_t	end_phy;
};

/*
 * Some hardware information like manufacturer, serial number, etc. are not
 * available via SMP or libsmhbaapi. This data is provided by the HC module,
 * however. The HC module does not have its tree constructed when this sas
 * module runs, so we need to register callbacks for these properties.
 *
 * The callbacks will look up the device specific properties in the HC tree
 * and copy them alongside the sas topo node.
 */
int
sas_prop_method_register(topo_mod_t *mod, tnode_t *tn, const char *pgname)
{
	const topo_method_t *propmethods;
	int ret = -1;

	if (strcmp(topo_node_name(tn), TOPO_VTX_INITIATOR) == 0)
		propmethods = sas_initiator_methods;
	else if (strcmp(topo_node_name(tn), TOPO_VTX_PORT) == 0)
		propmethods = sas_port_methods;
	else if (strcmp(topo_node_name(tn), TOPO_VTX_EXPANDER) == 0)
		propmethods = sas_expander_methods;
	else if (strcmp(topo_node_name(tn), TOPO_VTX_TARGET) == 0)
		propmethods = sas_target_methods;

	if (topo_method_register(mod, tn, propmethods) != 0) {
		topo_mod_dprintf(mod, "failed to register fmri"
		    "methods for %s=%" PRIx64, topo_node_name(tn),
		    topo_node_instance(tn));
		goto err;
	}

	int err;
	nvlist_t *nvl = NULL;
	(void) topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME);

	if (strcmp(pgname, TOPO_PGROUP_TARGET) == 0) {
		fnvlist_add_string(nvl, "pname", TOPO_PROP_TARGET_FMRI);

		if (topo_prop_method_register(tn, pgname, TOPO_PROP_TARGET_FMRI,
		    TOPO_TYPE_STRING, TOPO_METH_SAS2HC, nvl, &err) != 0) {
			topo_mod_dprintf(mod, "Failed to set "
			    "up hc fmri cb on %s=%" PRIx64 " (%s)",
			    topo_node_name(tn),
			    topo_node_instance(tn),
			    topo_strerror(err));
			goto err;
		}

		const char *props[] = {
		    TOPO_PROP_TARGET_MANUF,
		    TOPO_PROP_TARGET_MODEL,
		    TOPO_PROP_TARGET_SERIAL,
		    TOPO_PROP_TARGET_LABEL
		};

		for (uint_t i = 0; i < sizeof (props) / sizeof (props[0]);
		    i++) {
			fnvlist_remove(nvl, "pname");
			fnvlist_add_string(nvl, "pname", props[i]);

			if (topo_prop_method_register(tn, pgname,
			    props[i], TOPO_TYPE_STRING,
			    TOPO_METH_SAS_DEV_PROP, nvl, &err) != 0) {
				topo_mod_dprintf(mod, "Failed to set "
				    "up prop cb on %s=%" PRIx64 " (%s)",
				    topo_node_name(tn),
				    topo_node_instance(tn),
				    topo_strerror(err));
				goto err;
			}
		}

	} else if (strcmp(pgname, TOPO_PGROUP_INITIATOR) == 0) {
		fnvlist_add_string(nvl, "pname", TOPO_PROP_INITIATOR_FMRI);

		if (topo_prop_method_register(tn, pgname,
		    TOPO_PROP_INITIATOR_FMRI,
		    TOPO_TYPE_STRING, TOPO_METH_SAS2HC, nvl, &err) != 0) {
			topo_mod_dprintf(mod, "Failed to set "
			    "hc fmri cb on %s=%" PRIx64 " (%s)",
			    topo_node_name(tn),
			    topo_node_instance(tn),
			    topo_strerror(err));
			goto err;
		}

		const char *props[] = {
		    TOPO_PROP_INITIATOR_MANUF,
		    TOPO_PROP_INITIATOR_MODEL,
		    TOPO_PROP_INITIATOR_LABEL
			/*
			 * XXX: TOPO_PROP_INITIATOR_SERIAL
			 */
		};

		for (uint_t i = 0; i < sizeof (props) / sizeof (props[0]);
		    i++) {
			fnvlist_add_string(nvl, "pname", props[i]);

			if (topo_prop_method_register(tn, pgname, props[i],
			    TOPO_TYPE_STRING, TOPO_METH_SAS_DEV_PROP, nvl, &err)
			    != 0) {
				topo_mod_dprintf(mod, "Failed to set "
				    "up prop cb on %s=%" PRIx64 " (%s)",
				    topo_node_name(tn),
				    topo_node_instance(tn),
				    topo_strerror(err));
				goto err;
			}
		}
	} else if (strcmp(pgname, TOPO_PGROUP_SASPORT) == 0) {
		const char *props[] = {
		    TOPO_PROP_SASPORT_INV_DWORD,
		    TOPO_PROP_SASPORT_RUN_DISP,
		    TOPO_PROP_SASPORT_LOSS_SYNC,
		    TOPO_PROP_SASPORT_RESET_PROB
		};

		for (uint_t i = 0; i < sizeof (props) / sizeof (props[0]);
		    i++) {
			fnvlist_add_string(nvl, "pname", props[i]);

			if (topo_prop_method_register(tn, pgname, props[i],
			    TOPO_TYPE_UINT64_ARRAY, TOPO_METH_SAS_PHY_ERR, nvl,
			    &err) != 0) {
				topo_mod_dprintf(mod, "Failed to set "
				    "up prop cb on %s=%" PRIx64 " (%s)",
				    topo_node_name(tn),
				    topo_node_instance(tn),
				    topo_strerror(err));
				goto err;
			}
		}
	}
	nvlist_free(nvl);
	ret = 0;
err:
	return (ret);
}


static topo_vertex_t *
sas_create_vertex(topo_mod_t *mod, const char *name, topo_instance_t inst,
    struct sas_phy_info *phyinfo)
{
	topo_vertex_t *vtx;
	tnode_t *tn;
	topo_pgroup_info_t pgi;
	int err;
	nvlist_t *auth = NULL, *fmri = NULL;

	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (strcmp(name, TOPO_VTX_EXPANDER) == 0)
		pgi.tpi_name = TOPO_PGROUP_EXPANDER;
	else if (strcmp(name, TOPO_VTX_INITIATOR) == 0)
		pgi.tpi_name = TOPO_PGROUP_INITIATOR;
	else if (strcmp(name, TOPO_VTX_PORT) == 0)
		pgi.tpi_name = TOPO_PGROUP_SASPORT;
	else if (strcmp(name, TOPO_VTX_TARGET) == 0)
		pgi.tpi_name = TOPO_PGROUP_TARGET;
	else {
		topo_mod_dprintf(mod, "invalid vertex name: %s", name);
		return (NULL);
	}

	if ((vtx = topo_vertex_new(mod, name, inst)) == NULL) {
		/* errno set */
		topo_mod_dprintf(mod, "failed to create vertex: "
		    "%s=%" PRIx64 "", name, inst);
		return (NULL);
	}
	tn = topo_vertex_node(vtx);

	if (topo_mod_nvalloc(mod, &auth, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(auth, FM_FMRI_SAS_TYPE,
	    FM_FMRI_SAS_TYPE_PATHNODE) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	if (strcmp(name, TOPO_VTX_PORT) == 0 && phyinfo != NULL) {
		/*
		 * if (phyinfo == NULL) {
		 *	goto err;
		 * }
		 */
		if (nvlist_add_uint32(auth, FM_FMRI_SAS_START_PHY,
		    phyinfo->start_phy) != 0 ||
		    nvlist_add_uint32(auth, FM_FMRI_SAS_END_PHY,
		    phyinfo->end_phy) != 0) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			topo_mod_dprintf(mod, "failed to construct auth for "
			    "node: %s=%" PRIx64, name, inst);
			goto err;
		}
	}
	if ((fmri = topo_mod_sasfmri(mod, FM_SAS_SCHEME_VERSION, name, inst,
	    auth)) == NULL) {
		/* errno set */
		topo_mod_dprintf(mod, "failed to construct FMRI for "
		    "%s=%" PRIx64 ": %s", name, inst, topo_strerror(err));
		goto err;
	}
	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		(void) topo_mod_seterrno(mod, err);
		topo_mod_dprintf(mod, "failed to create %s propgroup on "
		    "%s=%" PRIx64 ": %s", pgi.tpi_name, name, inst,
		    topo_strerror(err));
		goto err;
	}
	if (topo_pgroup_create(tn, &protocol_pgroup, &err) < 0 ||
	    topo_prop_set_fmri(tn, TOPO_PGROUP_PROTOCOL, TOPO_PROP_RESOURCE,
	    TOPO_PROP_IMMUTABLE, fmri, &err) < 0) {
		(void) topo_mod_seterrno(mod, err);
		topo_mod_dprintf(mod, "failed to create %s propgroup on "
		    "%s=%" PRIx64 ": %s", TOPO_PGROUP_PROTOCOL, name, inst,
		    topo_strerror(err));
		goto err;
	}

	/*
	 * Make sure the appropriate methods to retrieve FMRIs and dynamic
	 * properties are configured for each node that corresponds to a
	 * hardware component.
	 */
	if (sas_prop_method_register(mod, tn, pgi.tpi_name) != 0) {
		topo_mod_dprintf(mod, "failed to register property "
		    "methods for %s=%" PRIx64, name, inst);
		goto err;
	}

	return (vtx);
err:
	nvlist_free(auth);
	topo_vertex_destroy(mod, vtx);
	return (NULL);
}

static uint64_t
wwn_to_uint64(HBA_WWN wwn)
{
	uint64_t res;
	(void) memcpy(&res, &wwn, sizeof (uint64_t));
	return (ntohll(res));
}

typedef struct sas_port {
	topo_list_t		sp_list;
	uint64_t		sp_att_wwn;
	topo_vertex_t		*sp_vtx; /* port pointer */
	boolean_t		sp_is_expander;
	boolean_t		sp_has_hba_connection;
} sas_port_t;

typedef struct sas_vtx_search {
	topo_instance_t	inst;
	const char	*name;
	topo_list_t	*result_list;
} sas_vtx_search_t;

typedef struct sas_vtx {
	topo_list_t	tds_list;
	topo_vertex_t	*tds_vtx;
} sas_vtx_t;

/* Finds vertices matching the given tn_instance and tn_name. */
int
sas_vtx_match(topo_hdl_t *thp, topo_vertex_t *vtx, boolean_t last,
    void *arg)
{
	sas_vtx_search_t *search = arg;
	sas_vtx_t *res = NULL;
	tnode_t *node = topo_vertex_node(vtx);

	if (node->tn_instance == search->inst &&
	    strcmp(node->tn_name, search->name) == 0) {
		res = topo_hdl_zalloc(thp, sizeof (sas_vtx_t));
		if (res != NULL) {
			res->tds_vtx = vtx;
			topo_list_append(search->result_list, res);
		}
	}
	return (TOPO_WALK_NEXT);
}

static uint_t
sas_find_connected_vtx(topo_mod_t *mod, uint64_t att_wwn, uint64_t search_wwn,
    const char *vtx_type, topo_list_t *res_list)
{
	topo_list_t *vtx_list = topo_mod_zalloc(mod, sizeof (topo_list_t));
	sas_vtx_search_t search;
	search.inst = search_wwn;
	search.name = vtx_type;
	search.result_list = vtx_list;
	sas_vtx_t *res;

	uint_t nfound = 0;

	(void) topo_vertex_iter(mod->tm_hdl, topo_digraph_get(mod->tm_hdl,
	    FM_FMRI_SCHEME_SAS), sas_vtx_match, &search);

	for (sas_vtx_t *res = topo_list_next(vtx_list);
	    res != NULL; res = topo_list_next(res)) {
		if (strcmp(vtx_type, TOPO_VTX_PORT) == 0 && att_wwn != 0) {
			/* The caller is looking for a specific linkage. */
			sas_port_t *res_port = topo_node_getspecific(
			    topo_vertex_node(res->tds_vtx));

			if ((res_port != NULL &&
			    res_port->sp_att_wwn != att_wwn) ||
			    res->tds_vtx->tvt_nincoming != 0)
				continue;

			sas_vtx_t *vtx = topo_mod_zalloc(
			    mod, sizeof (sas_vtx_t));
			vtx->tds_vtx = res->tds_vtx;
			topo_list_append(res_list, vtx);
			nfound++;
		} else if (strcmp(vtx_type, TOPO_VTX_EXPANDER) == 0) {
			/*
			 * The caller is looking for anything that matches
			 * search_wwn. There should only be one expander vtx
			 * matching this description.
			 */
			sas_vtx_t *vtx = topo_mod_zalloc(
			    mod, sizeof (sas_vtx_t));
			vtx->tds_vtx = res->tds_vtx;
			topo_list_append(res_list, vtx);
			nfound++;
		}
	}

	/* Clean up all the garbage used by the search routine. */
	res = topo_list_next(vtx_list);
	while (res != NULL) {
		sas_vtx_t *tmp = res;

		res = topo_list_next(res);
		topo_mod_free(mod, tmp, sizeof (sas_vtx_t));
	}
	topo_mod_free(mod, vtx_list, sizeof (topo_list_t));

	return (nfound);
}

static int
sas_expander_discover(topo_mod_t *mod, const char *smp_path,
    topo_list_t *expd_list)
{
	int ret = 0;
	int i;
	uint8_t *smp_resp, num_phys;
	uint64_t expd_addr;
	size_t smp_resp_len;

	smp_target_def_t *tdef = NULL;
	smp_target_t *tgt = NULL;
	smp_action_t *axn = NULL;
	smp_report_general_resp_t *report_resp = NULL;

	smp_function_t func;
	smp_result_t result;

	topo_vertex_t *expd_vtx = NULL;
	struct sas_phy_info phyinfo;
	sas_port_t *port_info = NULL;
	tnode_t *tn = NULL;
	int err;

	tdef = (smp_target_def_t *)topo_mod_zalloc(mod,
	    sizeof (smp_target_def_t));

	tdef->std_def = smp_path;

	if ((tgt = smp_open(tdef)) == NULL) {
		ret = -1;
		topo_mod_dprintf(mod, "failed to open SMP target\n");
		goto done;
	}

	axn = smp_action_alloc(func, tgt, 0);

	if (smp_exec(axn, tgt) != 0) {
		ret = -1;
		smp_action_free(axn);
		goto done;
	}

	smp_action_get_response(axn, &result, (void **) &smp_resp,
	    &smp_resp_len);
	smp_action_free(axn);

	if (result != SMP_RES_FUNCTION_ACCEPTED) {
		ret = -1;
		goto done;
	}

	report_resp = (smp_report_general_resp_t *)smp_resp;
	num_phys = report_resp->srgr_number_of_phys;
	expd_addr = ntohll(report_resp->srgr_enclosure_logical_identifier);

	phyinfo.start_phy = 0;
	phyinfo.end_phy = (phyinfo.start_phy + num_phys) - (num_phys - 1);
	if ((expd_vtx = sas_create_vertex(mod, TOPO_VTX_EXPANDER, expd_addr,
	    &phyinfo)) == NULL) {
		ret = -1;
		goto done;
	}
	port_info = topo_mod_zalloc(mod, sizeof (sas_port_t));
	port_info->sp_vtx = expd_vtx;
	port_info->sp_is_expander = B_TRUE;

	tn = topo_vertex_node(expd_vtx);
	topo_node_setspecific(tn, port_info);

	/* XXX get the /dev/smp/XYZ path instead of the /devices path? */
	if (topo_prop_set_string(tn, TOPO_PGROUP_EXPANDER,
	    TOPO_PROP_EXPANDER_DEVFSNAME, TOPO_PROP_IMMUTABLE,
	    smp_path, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set props on %s=%" PRIx64,
		    topo_node_name(tn), topo_node_instance(tn));
		ret = -1;
		goto done;
	}

	boolean_t wide_port_discovery = B_FALSE;
	uint64_t wide_port_att_wwn;
	struct sas_phy_info wide_port_phys;
	bzero(&wide_port_phys, sizeof (struct sas_phy_info));
	for (i = 0; i < num_phys; i++) {
		smp_discover_req_t *disc_req = NULL;
		smp_discover_resp_t *disc_resp = NULL;

		func = SMP_FUNC_DISCOVER;
		axn = smp_action_alloc(func, tgt, 0);
		smp_action_get_request(axn, (void **) &disc_req, NULL);
		disc_req->sdr_phy_identifier = i;

		if (smp_exec(axn, tgt) != 0) {
			topo_mod_dprintf(mod, "smp_exec failed\n");
			smp_action_free(axn);
			goto done;
		}

		smp_action_get_response(axn, &result, (void **) &smp_resp,
		    &smp_resp_len);
		smp_action_free(axn);

		disc_resp = (smp_discover_resp_t *)smp_resp;
		if (result != SMP_RES_FUNCTION_ACCEPTED &&
		    result != SMP_RES_PHY_VACANT) {
			topo_mod_dprintf(mod, "function not accepted\n");
			goto done;
		}

		if (result == SMP_RES_PHY_VACANT) {
			continue;
		}

		if (disc_resp->sdr_attached_device_type == SMP_DEV_SAS_SATA &&
		    (disc_resp->sdr_attached_ssp_target ||
		    disc_resp->sdr_attached_stp_target) &&
		    disc_resp->sdr_connector_type == 0x20 &&
		    !disc_resp->sdr_attached_smp_target &&
		    !disc_resp->sdr_attached_smp_initiator) {
			/*
			 * 0x20 == expander backplane receptacle.
			 * XXX We should use ses_sasconn_type_t enum from
			 * ses2.h. Acceptable values (as of SES-3): 0x20 - 0x2F.
			 *
			 * XXX sdr_attached_smp_initiator is B_TRUE for SMP
			 * devices. We should map these too, but for now ignore
			 * them. They likely need their own (empty?) property
			 * group.
			 */

			/*
			 * The current phy cannot be part of a wide
			 * port, so the previous wide port discovery
			 * effort must be committed.
			 */
			if (wide_port_discovery) {
				wide_port_discovery = B_FALSE;
				sas_port_t *expd_port = topo_mod_zalloc(
				    mod, sizeof (sas_port_t));

				expd_port->sp_att_wwn =
				    htonll(wide_port_att_wwn);
				expd_port->sp_is_expander = B_TRUE;
				if ((expd_port->sp_vtx =
				    sas_create_vertex(mod, TOPO_VTX_PORT,
				    expd_addr, &wide_port_phys)) == NULL) {
					topo_mod_free(mod, expd_port,
					    sizeof (sas_port_t));
					ret = -1;
					goto done;
				}
				topo_list_append(expd_list, expd_port);
				tn = topo_vertex_node(expd_port->sp_vtx);
				topo_node_setspecific(tn, expd_port);
				if (topo_prop_set_uint64(tn,
				    TOPO_PGROUP_SASPORT,
				    TOPO_PROP_SASPORT_LOCAL_ADDR,
				    TOPO_PROP_IMMUTABLE,
				    expd_addr, &err) != 0 ||
				    topo_prop_set_uint64(tn,
				    TOPO_PGROUP_SASPORT,
				    TOPO_PROP_SASPORT_ATTACH_ADDR,
				    TOPO_PROP_IMMUTABLE,
				    expd_port->sp_att_wwn, &err) != 0) {
					topo_mod_dprintf(mod,
					    "Failed to set props on "
					    "%s=%" PRIx64 " (%s)",
					    topo_node_name(tn),
					    topo_node_instance(tn),
					    topo_strerror(err));
					ret = -1;
					goto done;
				}
			}
			topo_vertex_t *ex_pt_vtx, *port_vtx, *tgt_vtx;

			/* Phy info for expander port is the expander's phy. */
			phyinfo.start_phy = disc_resp->sdr_phy_identifier;
			phyinfo.end_phy = disc_resp->sdr_phy_identifier;
			if ((ex_pt_vtx = sas_create_vertex(mod, TOPO_VTX_PORT,
			    ntohll(disc_resp->sdr_sas_addr),
			    &phyinfo)) == NULL) {
				ret = -1;
				goto done;
			}

			tn = topo_vertex_node(ex_pt_vtx);
			if (topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
			    TOPO_PROP_SASPORT_LOCAL_ADDR, TOPO_PROP_IMMUTABLE,
			    ntohll(disc_resp->sdr_sas_addr), &err) != 0 ||
			    topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
			    TOPO_PROP_SASPORT_ATTACH_ADDR, TOPO_PROP_IMMUTABLE,
			    ntohll(disc_resp->sdr_attached_sas_addr),
			    &err) != 0) {
				topo_mod_dprintf(mod, "Failed to set props on "
				    "%s=%" PRIx64,
				    topo_node_name(tn), topo_node_instance(tn));
				ret = -1;
				goto done;
			}

			if (topo_edge_new(mod, expd_vtx, ex_pt_vtx) != 0) {
				topo_vertex_destroy(mod, ex_pt_vtx);
				ret = -1;
				goto done;
			}

			/*
			 * Phy info for attached device port is the device's
			 * internal phy.
			 */
			phyinfo.start_phy =
			    disc_resp->sdr_attached_phy_identifier;
			phyinfo.end_phy =
			    disc_resp->sdr_attached_phy_identifier;
			if ((port_vtx = sas_create_vertex(mod, TOPO_VTX_PORT,
			    ntohll(disc_resp->sdr_attached_sas_addr),
			    &phyinfo)) == NULL) {
				topo_vertex_destroy(mod, ex_pt_vtx);
				ret = -1;
				goto done;
			}

			tn = topo_vertex_node(port_vtx);
			if (topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
			    TOPO_PROP_SASPORT_LOCAL_ADDR, TOPO_PROP_IMMUTABLE,
			    ntohll(disc_resp->sdr_attached_sas_addr), &err)
			    != 0 ||
			    topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
			    TOPO_PROP_SASPORT_ATTACH_ADDR, TOPO_PROP_IMMUTABLE,
			    ntohll(disc_resp->sdr_sas_addr), &err) != 0) {
				topo_mod_dprintf(mod, "Failed to set props on "
				    "%s=%" PRIx64 " (%s)",
				    topo_node_name(tn), topo_node_instance(tn),
				    topo_strerror(err));
				ret = -1;
				goto done;
			}

			if (topo_edge_new(mod, ex_pt_vtx, port_vtx) != 0) {
				topo_vertex_destroy(mod, ex_pt_vtx);
				topo_vertex_destroy(mod, port_vtx);
				ret = -1;
				goto done;
			}

			/* This is a target disk. */
			if ((tgt_vtx = sas_create_vertex(mod, TOPO_VTX_TARGET,
			    ntohll(disc_resp->sdr_attached_sas_addr),
			    &phyinfo)) == NULL) {
				topo_vertex_destroy(mod, ex_pt_vtx);
				topo_vertex_destroy(mod, port_vtx);
				ret = -1;
				goto done;
			}

			if (topo_edge_new(mod, port_vtx, tgt_vtx) != 0) {
				topo_vertex_destroy(mod, ex_pt_vtx);
				topo_vertex_destroy(mod, port_vtx);
				topo_vertex_destroy(mod, tgt_vtx);
				ret = -1;
				goto done;
			}

			tn = topo_vertex_node(tgt_vtx);

		} else if (disc_resp->sdr_attached_device_type
		    == SMP_DEV_EXPANDER ||
		    (disc_resp->sdr_attached_ssp_initiator ||
		    disc_resp->sdr_attached_stp_initiator ||
		    disc_resp->sdr_attached_smp_initiator)) {
			/*
			 * This phy is for another 'complicated' device like an
			 * expander or an HBA. This phy may be in a wide port
			 * configuration.
			 *
			 * To discover wide ports we allow the phy discovery
			 * loop to continue to run. When this block
			 * first encounters a possibly wide port it sets the
			 * start phy to the current phy, and it is not modified
			 * again.
			 *
			 * Each time this block finds the same attached SAS
			 * address we update the end phy identifier to be the
			 * current phy.
			 *
			 * Once the phy discovery loop finds a new attached SAS
			 * address we know that the (possibly) wide port is done
			 * being discovered and it should be 'committed.'
			 */

			/*
			 * The current phy cannot be part of a wide
			 * port, so the previous wide port discovery
			 * effort must be committed.
			 */
			if (disc_resp->sdr_attached_sas_addr
			    != wide_port_att_wwn && wide_port_discovery) {
				wide_port_discovery = B_FALSE;
				sas_port_t *expd_port = topo_mod_zalloc(
				    mod, sizeof (sas_port_t));

				expd_port->sp_att_wwn =
				    htonll(wide_port_att_wwn);
				expd_port->sp_is_expander = B_TRUE;
				if ((expd_port->sp_vtx =
				    sas_create_vertex(mod, TOPO_VTX_PORT,
				    expd_addr, &wide_port_phys)) == NULL) {
					topo_mod_free(mod, expd_port,
					    sizeof (sas_port_t));
					ret = -1;
					goto done;
				}
				topo_list_append(expd_list, expd_port);
				tn = topo_vertex_node(expd_port->sp_vtx);
				topo_node_setspecific(tn, expd_port);
				if (topo_prop_set_uint64(tn,
				    TOPO_PGROUP_SASPORT,
				    TOPO_PROP_SASPORT_LOCAL_ADDR,
				    TOPO_PROP_IMMUTABLE,
				    expd_addr, &err) != 0 ||
				    topo_prop_set_uint64(tn,
				    TOPO_PGROUP_SASPORT,
				    TOPO_PROP_SASPORT_ATTACH_ADDR,
				    TOPO_PROP_IMMUTABLE,
				    expd_port->sp_att_wwn, &err) != 0) {
					topo_mod_dprintf(mod,
					    "Failed to set props on "
					    "%s=%" PRIx64 " (%s)",
					    topo_node_name(tn),
					    topo_node_instance(tn),
					    topo_strerror(err));
					ret = -1;
					goto done;
				}
			}

			if (!wide_port_discovery) {
				/* New wide port discovery run. */
				wide_port_discovery = B_TRUE;
				wide_port_phys.start_phy =
				    disc_resp->sdr_phy_identifier;
				wide_port_att_wwn =
				    disc_resp->sdr_attached_sas_addr;
			}

			wide_port_phys.end_phy =
			    disc_resp->sdr_phy_identifier;
		}
	}

done:
	smp_close(tgt);
	topo_mod_free(mod, tdef, sizeof (smp_target_def_t));
	return (ret);
}

typedef struct sas_topo_iter {
	topo_mod_t	*sas_mod;
	uint64_t	sas_search_wwn;
	topo_list_t	*sas_expd_list;
} sas_topo_iter_t;

/* Responsible for creating links from HBA -> fanout expanders. */
static int
sas_connect_hba(topo_hdl_t *hdl, topo_edge_t *edge, boolean_t last, void* arg)
{
	sas_topo_iter_t *iter = arg;
	tnode_t *node = topo_vertex_node(edge->tve_vertex);
	sas_port_t *hba_port = topo_node_getspecific(node);
	topo_vertex_t *expd_port_vtx = NULL;
	topo_vertex_t *expd_vtx = NULL;
	sas_port_t *expd_port = NULL;
	sas_vtx_t *vtx;

	topo_list_t *vtx_list = topo_mod_zalloc(
	    iter->sas_mod, sizeof (topo_list_t));

	if (strcmp(node->tn_name, TOPO_VTX_PORT) == 0 &&
	    edge->tve_vertex->tvt_noutgoing == 0) {
		/*
		 * This is a port vtx that isn't connected to anything. We need
		 * to:
		 * - find the expander port that this hba port is connected to.
		 * - if not already connected, connect the expander port to the
		 *   expander itself.
		 */
		uint_t nfound = sas_find_connected_vtx(iter->sas_mod,
		    node->tn_instance, hba_port->sp_att_wwn, TOPO_VTX_PORT,
		    vtx_list);

		/*
		 * XXX need to match up the phys in case this expd is
		 * connected to more than one hba. In that case nfound should be
		 * > 1.
		 */
		if (nfound > 1)
			goto out;
		sas_vtx_t *vtx = topo_list_next(vtx_list);
		expd_port_vtx = vtx->tds_vtx;
		if (expd_port_vtx == NULL ||
		    topo_edge_new(iter->sas_mod, edge->tve_vertex,
		    expd_port_vtx) != 0) {
			goto out;
		}
		topo_list_delete(vtx_list, vtx);
		topo_mod_free(iter->sas_mod, vtx, sizeof (sas_vtx_t));

		nfound = sas_find_connected_vtx(iter->sas_mod,
		    0, /* expd vtx doesn't have an attached SAS addr */
		    topo_vertex_node(expd_port_vtx)->tn_instance,
		    TOPO_VTX_EXPANDER, vtx_list);

		/* There should only be one expander vtx with this SAS addr. */
		if (nfound > 1)
			goto out;
		expd_vtx =
		    ((sas_vtx_t *)topo_list_next(vtx_list))->tds_vtx;
		if (expd_vtx == NULL ||
		    topo_edge_new(iter->sas_mod, expd_port_vtx,
		    expd_vtx) != 0) {
			goto out;
		}
		expd_port = topo_node_getspecific(topo_vertex_node(expd_vtx));
		expd_port->sp_has_hba_connection = B_TRUE;
	}

out:
	vtx = topo_list_next(vtx_list);
	while (vtx != NULL) {
		sas_vtx_t *tmp = vtx;

		vtx = topo_list_next(vtx);
		topo_mod_free(iter->sas_mod, tmp, sizeof (sas_vtx_t));
	}
	topo_mod_free(iter->sas_mod, vtx_list, sizeof (topo_list_t));

	return (TOPO_WALK_NEXT);
}

static int
sas_expd_interconnect(topo_hdl_t *hdl, topo_vertex_t *vtx,
    sas_topo_iter_t *iter)
{
	int ret = 0;
	tnode_t *node = topo_vertex_node(vtx);
	topo_list_t *list = topo_mod_zalloc(
	    iter->sas_mod, sizeof (topo_list_t));
	sas_port_t *port = topo_node_getspecific(node);
	topo_vertex_t *port_vtx = NULL;
	sas_vtx_t *disc_vtx;

	uint_t nfound = sas_find_connected_vtx(iter->sas_mod, node->tn_instance,
	    port->sp_att_wwn, TOPO_VTX_PORT, list);

	if (nfound == 0) {
		ret = -1;
		goto out;
	}

	/*
	 * XXX make this work for multiple expd <-> expd connections. Likely
	 * need to compare local/att port phys.
	 */
	if ((port_vtx = ((sas_vtx_t *)topo_list_next(list))->tds_vtx) == NULL) {
		ret = -1;
		goto out;
	}

	if (topo_edge_new(iter->sas_mod, vtx, port_vtx) != 0) {
		goto out;
	}

out:
	disc_vtx = topo_list_next(list);
	while (disc_vtx) {
		sas_vtx_t *tmp = disc_vtx;

		disc_vtx = topo_list_next(disc_vtx);
		topo_mod_free(iter->sas_mod, tmp, sizeof (sas_vtx_t));
	}
	topo_mod_free(iter->sas_mod, list, sizeof (topo_list_t));

	return (ret);
}

/*
 * This routine is responsible for connecting expander port vertices to their
 * associated expander. The trick is getting the 'direction' of the connection
 * correct since SMP does not provide this information.
 */
static int
sas_connect_expd(topo_hdl_t *hdl, topo_vertex_t *vtx, sas_topo_iter_t *iter)
{
	int ret = 0;
	tnode_t *node = topo_vertex_node(vtx);
	topo_vertex_t *expd_vtx = NULL;
	sas_port_t *disc_expd = NULL;
	sas_vtx_t *disc_vtx;

	topo_list_t *list = topo_mod_zalloc(
	    iter->sas_mod, sizeof (topo_list_t));

	/* Find the port's corresponding expander vertex. */
	uint_t nfound = sas_find_connected_vtx(iter->sas_mod, 0,
	    node->tn_instance, TOPO_VTX_EXPANDER, list);
	if (nfound == 0) {
		ret = -1;
		goto out;
	}

	if ((expd_vtx = ((sas_vtx_t *)topo_list_next(list))->tds_vtx) == NULL) {
		ret = -1;
		goto out;
	}

	disc_expd = topo_node_getspecific(topo_vertex_node(expd_vtx));
	/*
	 * XXX This assumes only one of the expanders is connected to an HBA.
	 * It should be possible for two expanders to both be connected to HBAs
	 * and also connected to each other. However, if we do this today the
	 * path finding logic in topo ends up doing infinite recursion trying
	 * to find targets.
	 */
	if (!disc_expd->sp_has_hba_connection) {
		if (topo_edge_new(iter->sas_mod, vtx, expd_vtx) != 0) {
			goto out;
		}
	} else {
		if (topo_edge_new(iter->sas_mod, expd_vtx, vtx) != 0) {
			goto out;
		}
	}

out:
	disc_vtx = topo_list_next(list);
	while (disc_vtx) {
		sas_vtx_t *tmp = disc_vtx;

		disc_vtx = topo_list_next(disc_vtx);
		topo_mod_free(iter->sas_mod, tmp, sizeof (sas_vtx_t));
	}
	topo_mod_free(iter->sas_mod, list, sizeof (topo_list_t));

	return (ret);
}

static int
sas_vtx_final_pass(topo_hdl_t *hdl, topo_vertex_t *vtx, boolean_t last,
    void *arg)
{
	sas_topo_iter_t *iter = arg;
	tnode_t *node = topo_vertex_node(vtx);
	sas_port_t *port = topo_node_getspecific(node);

	if (node != NULL && strcmp(node->tn_name, TOPO_VTX_PORT) == 0) {
		/*
		 * Connect this outbound port to another expander's inbound
		 * port.
		 */
		if (port != NULL && port->sp_vtx->tvt_noutgoing == 0 &&
		    port->sp_is_expander) {
			(void) sas_expd_interconnect(hdl, vtx, iter);
		}
	}

	return (0);
}

static int
sas_vtx_iter(topo_hdl_t *hdl, topo_vertex_t *vtx, boolean_t last, void *arg)
{
	sas_topo_iter_t *iter = arg;
	tnode_t *node = topo_vertex_node(vtx);
	sas_port_t *port = topo_node_getspecific(node);

	if (strcmp(node->tn_name, TOPO_VTX_INITIATOR) == 0) {
		(void) topo_edge_iter(hdl, vtx, sas_connect_hba, iter);
	} else if (strcmp(node->tn_name, TOPO_VTX_PORT) == 0) {

		/* Connect the port to its expander vtx. */
		if (port != NULL && port->sp_is_expander &&
		    port->sp_vtx->tvt_nincoming == 0)
			(void) sas_connect_expd(hdl, vtx, iter);

	}
	return (TOPO_WALK_NEXT);
}

typedef struct sas_hba_enum {
	HBA_HANDLE handle;
	SMHBA_ADAPTERATTRIBUTES *ad_attrs;
	uint_t port;
	topo_vertex_t *initiator;
	topo_list_t *hba_list;
	char aname[256];
} sas_hba_enum_t;

static int
sas_enum_hba_port(topo_mod_t *mod, sas_hba_enum_t *hbadata)
{
	SMHBA_PORTATTRIBUTES *attrs = NULL;
	SMHBA_SAS_PORT *sas_port;
	SMHBA_SAS_PHY phy_attrs;
	HBA_UINT32 num_phys;
	uint64_t hba_wwn;
	struct sas_phy_info phyinfo;
	sas_port_t *sas_hba_port = NULL;
	tnode_t *tn;
	int err, ret;
	topo_vertex_t *hba_port = NULL, *dev_port = NULL;
	topo_vertex_t *dev = NULL;

	attrs = topo_mod_zalloc(mod, sizeof (SMHBA_PORTATTRIBUTES));
	sas_port = topo_mod_zalloc(mod, sizeof (SMHBA_SAS_PORT));
	attrs->PortSpecificAttribute.SASPort = sas_port;

	if ((ret = SMHBA_GetAdapterPortAttributes(hbadata->handle,
	    hbadata->port, attrs)) != HBA_STATUS_OK) {
		goto err;
	}
	hba_wwn = wwn_to_uint64(sas_port->LocalSASAddress);
	num_phys = sas_port->NumberofPhys;

	/*
	 * Only create one logical initiator vertex for all of the HBA ports.
	 */
	/*
	 * XXX what to use for HBA phy info?
	 * phyinfo.start_phy = 0;
	 * phyinfo.end_phy = num_phys - 1;
	 */
	if (hbadata->initiator == NULL) {
		if ((hbadata->initiator = sas_create_vertex(mod,
		    TOPO_VTX_INITIATOR, hba_wwn, NULL)) == NULL) {
			goto err;
		}

		/*
		 * Set the devfs name for this initiator so we
		 * can use it to correlate with hc topo nodes
		 * later to retrieve info like dev manufacturer.
		 *
		 * The info we get from libsmhbaapi w.r.t.
		 * manufacturer, serial number, model, etc.
		 * appears to be inaccurate, so we'll defer to
		 * consulting the hc module later.
		 */
		tn = topo_vertex_node(hbadata->initiator);
		if (topo_prop_set_string(tn, TOPO_PGROUP_INITIATOR,
		    TOPO_PROP_INITIATOR_DEVFSNAME, TOPO_PROP_IMMUTABLE,
		    hbadata->ad_attrs->HBASymbolicName, &err) != 0) {
			goto err;
		}
	}

	/* Calculate the beginning and end phys for this port */
	for (uint_t phy = 0; phy < num_phys; phy++) {
		if ((ret = SMHBA_GetSASPhyAttributes(hbadata->handle,
		    hbadata->port, phy, &phy_attrs)) != HBA_STATUS_OK) {
			topo_mod_free(mod, attrs,
			    sizeof (SMHBA_PORTATTRIBUTES));
			topo_mod_free(mod, sas_port,
			    sizeof (SMHBA_SAS_PORT));
			goto err;
		}

		if (phy == 0) {
			phyinfo.start_phy =  phy_attrs.PhyIdentifier;
		}
		phyinfo.end_phy = phy_attrs.PhyIdentifier;
	}

	if ((hba_port = sas_create_vertex(mod, TOPO_VTX_PORT, hba_wwn,
	    &phyinfo)) == NULL) {
		goto err;
	}

	tn = topo_vertex_node(hba_port);

	if (topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_LOCAL_ADDR, TOPO_PROP_IMMUTABLE,
	    hba_wwn, &err) != 0 ||
	    topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_ATTACH_ADDR, TOPO_PROP_IMMUTABLE,
	    wwn_to_uint64(sas_port->AttachedSASAddress), &err) != 0 ||
	    topo_prop_set_string(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_ANAME, TOPO_PROP_IMMUTABLE, hbadata->aname,
	    &err) != 0 ||
	    topo_prop_set_uint32(tn, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_APORT, TOPO_PROP_IMMUTABLE, hbadata->port,
	    &err) != 0) {

		topo_mod_dprintf(mod, "Failed to set props on %s=%" PRIx64
		    " (%s)", topo_node_name(tn), topo_node_instance(tn),
		    topo_strerror(err));
		goto err;
	}

	/*
	 * Record that we created a unique port for this HBA.
	 * This will be referenced later if there are expanders in the
	 * topology.
	 */
	sas_hba_port = topo_mod_zalloc(mod, sizeof (sas_port_t));
	sas_hba_port->sp_att_wwn = wwn_to_uint64(
	    sas_port->AttachedSASAddress);
	sas_hba_port->sp_vtx = hba_port;

	topo_list_append(hbadata->hba_list, sas_hba_port);
	topo_node_setspecific(tn, sas_hba_port);

	if (topo_edge_new(mod, hbadata->initiator, hba_port) != 0) {
		goto err;
	}

	if (attrs->PortType == HBA_PORTTYPE_SASDEVICE) {
		/*
		 * Discovered a SAS or STP device connected directly to the
		 * HBA. This can sometimes include expander devices.
		 */
		if (sas_port->NumberofDiscoveredPorts > 1) {
			goto done;
		}

		/*
		 * SMHBAAPI doesn't give us attached device phy information.
		 * For HBA_PORTTYPE_SASDEVICE only phy 0 will be in use, unless
		 * there are virtual phys.
		 */
		phyinfo.start_phy = 0;
		phyinfo.end_phy = 0;
		if ((dev_port = sas_create_vertex(mod, TOPO_VTX_PORT,
		    wwn_to_uint64(sas_port->AttachedSASAddress),
		    &phyinfo)) == NULL) {
			goto err;
		}

		tn = topo_vertex_node(dev_port);
		if (topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
		    TOPO_PROP_SASPORT_LOCAL_ADDR, TOPO_PROP_IMMUTABLE,
		    wwn_to_uint64(sas_port->AttachedSASAddress), &err) != 0 ||
		    topo_prop_set_uint64(tn, TOPO_PGROUP_SASPORT,
		    TOPO_PROP_SASPORT_ATTACH_ADDR, TOPO_PROP_IMMUTABLE,
		    hba_wwn, &err) != 0) {

			topo_mod_dprintf(mod, "Failed to set props on %s=%"
			    PRIx64 " (%s)", topo_node_name(tn),
			    topo_node_instance(tn), topo_strerror(err));
			goto err;
		}

		if ((dev = sas_create_vertex(mod, TOPO_VTX_TARGET,
		    wwn_to_uint64(sas_port->AttachedSASAddress), &phyinfo))
		    == NULL) {
			goto err;
		}

		tn = topo_vertex_node(dev);
		if (topo_edge_new(mod, hba_port, dev_port) != 0 ||
		    topo_edge_new(mod, dev_port, dev) != 0) {
			goto err;
		}
	} else { /* Expanders? */
		goto done;
	}
done:
	topo_mod_free(mod, attrs, sizeof (SMHBA_PORTATTRIBUTES));
	topo_mod_free(mod, sas_port, sizeof (SMHBA_SAS_PORT));
	return (0);

err:
	topo_mod_free(mod, attrs, sizeof (SMHBA_PORTATTRIBUTES));
	topo_mod_free(mod, sas_port, sizeof (SMHBA_SAS_PORT));

	if (hbadata->initiator != NULL)
		topo_vertex_destroy(mod, hbadata->initiator);
	if (hba_port != NULL)
		topo_vertex_destroy(mod, hba_port);
	if (dev_port != NULL)
		topo_vertex_destroy(mod, dev_port);
	if (dev != NULL)
		topo_vertex_destroy(mod, dev);
	return (-1);
}

static int
sas_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	if (topo_method_register(mod, rnode, sas_root_methods) != 0) {
		topo_mod_dprintf(mod, "failed to register scheme methods");
		/* errno set */
		return (-1);
	}

	if (getenv("TOPO_SASNOENUM"))
		return (0);

	int ret = -1;

	di_node_t root, smp;
	const char *smp_path = NULL;
	sas_port_t *expd_port, *hba_port;
	topo_list_t *expd_list = topo_mod_zalloc(mod, sizeof (topo_list_t));
	topo_list_t *hba_list = topo_mod_zalloc(mod, sizeof (topo_list_t));

	/* Begin by discovering all HBAs and their immediate ports. */
	HBA_HANDLE handle;
	SMHBA_ADAPTERATTRIBUTES ad_attrs;
	HBA_UINT32 num_ports, num_adapters;

	num_adapters = HBA_GetNumberOfAdapters();
	if (num_adapters == 0) {
		ret = 0;
		goto done;
	}

	for (uint_t i = 0; i < num_adapters; i++) {
		sas_hba_enum_t hbadata = { 0 };

		if ((ret = HBA_GetAdapterName(i, hbadata.aname)) != 0) {
			topo_mod_dprintf(mod, "failed to get adapter name\n");
			goto done;
		}

		if ((handle = HBA_OpenAdapter(hbadata.aname)) == 0) {
			topo_mod_dprintf(mod, "failed to open adapter\n");
			goto done;
		}

		if ((ret = SMHBA_GetAdapterAttributes(handle, &ad_attrs)) !=
		    HBA_STATUS_OK) {
			topo_mod_dprintf(mod, "failed to get adapter attrs\n");
			HBA_CloseAdapter(handle);
			goto done;
		}

		if ((ret = SMHBA_GetNumberOfPorts(handle, &num_ports)) !=
		    HBA_STATUS_OK) {
			topo_mod_dprintf(mod, "failed to get num ports\n");
			HBA_CloseAdapter(handle);
			goto done;
		}

		hbadata.handle = handle;
		hbadata.ad_attrs = &ad_attrs;
		hbadata.hba_list = hba_list;
		for (uint_t port = 0; port < num_ports; port++) {
			hbadata.port = port;
			if (sas_enum_hba_port(mod, &hbadata) != 0) {
				HBA_CloseAdapter(handle);
				goto done;
			}
		}
		HBA_CloseAdapter(handle);
	}

	/* Iterate through the expanders in /dev/smp. */
	/* XXX why does topo_mod_devinfo() return ENOENT? */
	root = di_init("/", DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		topo_mod_dprintf(mod, "di_init failed %s\n", strerror(errno));
		goto done;
	}

	for (smp = di_drv_first_node("smp", root);
	    smp != DI_NODE_NIL;
	    smp = di_drv_next_node(smp)) {
		char *full_smp_path;

		smp_path = di_devfs_path(smp);
		full_smp_path = topo_mod_zalloc(
		    mod, strlen(smp_path) + strlen("/devices"));
		(void) sprintf(full_smp_path, "/devices%s:smp", smp_path);

		if (sas_expander_discover(mod, full_smp_path,
		    expd_list) != 0) {
			topo_mod_dprintf(mod, "expander discovery failed\n");
			goto done;
		}
	}

	sas_topo_iter_t iter;
	iter.sas_mod = mod;
	iter.sas_expd_list = expd_list;
	(void) topo_vertex_iter(mod->tm_hdl,
	    topo_digraph_get(mod->tm_hdl, FM_FMRI_SCHEME_SAS),
	    sas_vtx_iter, &iter);

	(void) topo_vertex_iter(mod->tm_hdl,
	    topo_digraph_get(mod->tm_hdl, FM_FMRI_SCHEME_SAS),
	    sas_vtx_final_pass, &iter);

	ret = 0;
done:
	expd_port = topo_list_next(expd_list);
	while (expd_port != NULL) {
		sas_port_t *tmp = expd_port;

		expd_port = topo_list_next(expd_port);
		topo_mod_free(mod, tmp, sizeof (sas_port_t));
	}
	topo_mod_free(mod, expd_list, sizeof (topo_list_t));

	hba_port = topo_list_next(hba_list);
	while (hba_port != NULL) {
		sas_port_t *tmp = hba_port;

		hba_port = topo_list_next(hba_port);
		topo_mod_free(mod, tmp, sizeof (sas_port_t));
	}
	topo_mod_free(mod, hba_list, sizeof (topo_list_t));

	return (ret);
}

static void
sas_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

typedef struct sas_topo_cbarg {
	topo_mod_t *st_mod;
	tnode_t *st_node;
	void *st_ret;
} sas_topo_cbarg_t;

/*
 * XXX still need to implement this.
 * This is a prop method that returns the dev-scheme FMRI of the component.
 * This should be registered on the underlying nodes for initiator, expander
 * and target vertices.
 */
static int
sas_dev_fmri(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	return (-1);
}

/*
 * Called for every node in the hc tree. This function determines if the given
 * hc node corresponds to the sas node in arg->st_node. If the two nodes refer
 * to the same device then we retrieve the resource string and copy it into
 * the sas node's property group.
 *
 * The hc resource is later used to associate other hc properties, like serial
 * number, device manufacturer, etc. with sas nodes.
 */
int
hc_iter_cb(topo_hdl_t *thp, tnode_t *node, void *arg)
{
	sas_topo_cbarg_t *cbarg = (sas_topo_cbarg_t *)arg;
	tnode_t *sas_node = cbarg->st_node;
	int err = 0;
	nvlist_t *fmri = NULL;
	char *fmristr = NULL;
	tnode_t *targ_node = NULL;
	topo_mod_t *mod = cbarg->st_mod;

	if (strcmp(topo_node_name(node), PCIEX_FUNCTION) == 0 &&
	    strcmp(topo_node_name(sas_node), TOPO_VTX_INITIATOR) == 0) {
		char *sas_devfsn = NULL;
		char *hc_devfsn = NULL;

		if (topo_prop_get_string(sas_node, TOPO_PGROUP_INITIATOR,
		    TOPO_PROP_INITIATOR_DEVFSNAME, &sas_devfsn, &err) != 0) {
			topo_mod_dprintf(mod, "failed to find"
			    " devfsname (%s)", topo_strerror(err));
			goto done;
		}

		if (topo_prop_get_fmri(node, TOPO_PGROUP_IO,
		    TOPO_IO_MODULE, &fmri, &err) != 0 ||
		    topo_prop_get_string(node, TOPO_PGROUP_IO,
		    TOPO_IO_DEV, &hc_devfsn, &err) != 0) {
			topo_mod_dprintf(mod, "failed to get IO props"
			    " (%s)", topo_strerror(err));
			goto done;
		}

		/*
		 * Match sas and hc topo nodes based on the discovered
		 * OS device names.
		 *
		 * The libsmhbaapi reported device name includes the leading
		 * '/devices' string. The hc device name doesn't include this,
		 * so we advance the pointer a bit to make the comparison.
		 */
		sas_devfsn += strlen("/devices");
		if (strcmp(sas_devfsn, hc_devfsn) != 0) {
			goto done;
		}

		/*
		 * We expect initiators to be using the mpt_sas driver.
		 * This won't work for non-mpt_sas topologies, but
		 * by this point those topos have already been
		 * ignored.
		 */
		(void) nvlist_lookup_string(fmri, FM_FMRI_MOD_NAME,
		    &fmristr);
		if (strcmp(fmristr, "mpt_sas") != 0) {
			goto done;
		}

		targ_node = node;

	} else if (strcmp(topo_node_name(node), DISK) == 0 &&
	    strcmp(topo_node_name(sas_node), TOPO_VTX_TARGET) == 0) {

		char *ldisk;
		uint64_t wwn;
		if (topo_prop_get_string(node, TOPO_PGROUP_STORAGE,
		    "logical-disk", &ldisk, &err) != 0) { /* XXX fix string */
			topo_mod_dprintf(mod, "failed to get devid (%s)",
			    topo_strerror(err));
			goto done;
		}
		/*
		 * We get a logical-disk name that looks like this: c0tWWNd0
		 *
		 * We want to compare the middle WWN part to the sas node's WWN.
		 * Once we pull the middle bit out we convert it to a uint64 so
		 * comparison is easier.
		 */
		ldisk = strchr(ldisk, 't');
		ldisk++;
		ldisk = strtok(ldisk, "d");

		(void) scsi_wwnstr_to_wwn(ldisk, &wwn);
		if (wwn == topo_node_instance(sas_node)) {
			targ_node = node;
		} else if ((wwn - 0x2) == topo_node_instance(sas_node)) {
			/*
			 * XXX magma machine reports WWNs that are off-by-2.
			 * We should figure out why that is.
			 */
			targ_node = node;
		}
	}

	if (targ_node == NULL) {
		goto done;
	}

	if (topo_node_resource(targ_node, &fmri, &err) != 0 ||
	    topo_fmri_nvl2str(thp, fmri, &fmristr, &err) != 0) {
		topo_mod_dprintf(mod, "failed to get"
		    "resource string (%s)", topo_strerror(err));
		goto done;
	}
	cbarg->st_ret = fmristr;
	return (TOPO_WALK_TERMINATE);

done:
	return (TOPO_WALK_NEXT);
}

/*
 * This is a prop method that returns the hc-scheme FMRI of the corresponding
 * component in the hc-scheme topology.  This should be registered on the
 * underlying nodes for initiator and non-SMP target vertices.
 *
 * For initiators this would be the corresponding pciexfn node.
 * For disk/ssd targets, this would be the corresponding disk node.  For SES
 * targets, this would be the corresponding ses-enclosure node.  SMP targets
 * are not represented in the hc-scheme topology.
 */
static int
sas_hc_fmri(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	topo_hdl_t *thp = mod->tm_hdl;
	topo_walk_t *twp = NULL;
	sas_topo_cbarg_t cbarg = {
		.st_mod = mod,
		.st_node = node
	};
	int err;
	nvlist_t *result = NULL;
	const char *pname = NULL;

	if ((twp = topo_walk_init(thp, "hc", hc_iter_cb, &cbarg, &err))
	    == NULL) {
		topo_mod_dprintf(mod, "failed to init topo walker: %s",
		    topo_strerror(err));
		goto out;
	}
	if (topo_walk_step(twp, TOPO_WALK_CHILD) == TOPO_WALK_ERR) {
		topo_mod_dprintf(mod, "topo walker error");
		topo_walk_fini(twp);
		goto out;
	}
	topo_walk_fini(twp);

	if (cbarg.st_ret == NULL) {
		err = -1;
		goto out;
	}

	(void) topo_mod_nvalloc(mod, &result, NV_UNIQUE_NAME);
	if (strcmp(topo_node_name(node), TOPO_VTX_INITIATOR) == 0) {
		pname = TOPO_PROP_INITIATOR_FMRI;
	} else {
		pname = TOPO_PROP_TARGET_FMRI;
	}

	fnvlist_add_string(result, TOPO_PROP_VAL_NAME, pname);
	fnvlist_add_uint32(result, TOPO_PROP_VAL_TYPE, TOPO_TYPE_STRING);
	fnvlist_add_string(result, TOPO_PROP_VAL_VAL, strdup(cbarg.st_ret));
	*out = result;

out:
	return (err);
}

/*
 * This is the entrypoint for gathering stats from other modules.
 *
 * This will first look up the hc scheme fmri. The hc fmri is then used to look
 * up various other properties that are relevant to the sas devices.
 */
static int
sas_device_props_set(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	topo_hdl_t *thp = mod->tm_hdl;
	const char *pgroup = NULL;
	const char *pname = NULL;
	const char *fmri_pname = NULL;
	char *val = NULL;
	nvlist_t *nvl = NULL;
	nvlist_t *pnvl = NULL;
	const char *targ_group = NULL;
	const char *targ_prop = NULL;
	int err;

	nvl = fnvlist_lookup_nvlist(in, TOPO_PROP_ARGS);
	pname = fnvlist_lookup_string(nvl, "pname");

	if (strcmp(topo_node_name(node), TOPO_VTX_INITIATOR) == 0) {
		pgroup = TOPO_PGROUP_INITIATOR;
		fmri_pname = TOPO_PROP_INITIATOR_FMRI;
		if (strcmp(pname, TOPO_PROP_INITIATOR_MANUF) == 0) {
			targ_group = TOPO_PGROUP_PCI;
			targ_prop = TOPO_PCI_VENDNM;
		} else if (strcmp(pname, TOPO_PROP_INITIATOR_MODEL) == 0) {
			targ_group = TOPO_PGROUP_PCI;
			targ_prop = TOPO_PCI_DEVNM;
		} else if (strcmp(pname, TOPO_PROP_INITIATOR_LABEL) == 0) {
			targ_group = TOPO_PGROUP_PROTOCOL;
			targ_prop = TOPO_PROP_LABEL;
		}
	} else if (strcmp(topo_node_name(node), TOPO_VTX_TARGET) == 0) {
		pgroup = TOPO_PGROUP_TARGET;
		fmri_pname = TOPO_PROP_TARGET_FMRI;
		if (strcmp(pname, TOPO_PROP_TARGET_MANUF) == 0) {
			targ_group = TOPO_PGROUP_STORAGE;
			targ_prop = TOPO_STORAGE_MANUFACTURER;
		} else if (strcmp(pname, TOPO_PROP_TARGET_MODEL) == 0) {
			targ_group = TOPO_PGROUP_STORAGE;
			targ_prop = TOPO_STORAGE_MODEL;
		} else if (strcmp(pname, TOPO_PROP_TARGET_SERIAL) == 0) {
			targ_group = TOPO_PGROUP_STORAGE;
			targ_prop = "serial-number";
			/*
			 * XXX TOPO_STORAGE_SERIAL_NUM;
			 * from ../modules/common/disk/disk.h
			 */
		} else if (strcmp(pname, TOPO_PROP_TARGET_LABEL) == 0) {
			targ_group = TOPO_PGROUP_PROTOCOL;
			targ_prop = TOPO_PROP_LABEL;
		}
	}

	if (topo_prop_get_string(node, pgroup, fmri_pname, &val, &err) != 0) {
		topo_mod_dprintf(mod, "failed to get fmri for %s=%" PRIx64
		    " (%s)", topo_node_name(node), topo_node_instance(node),
		    topo_strerror(err));
		goto done;
	}

	if (topo_fmri_str2nvl(thp, val, &nvl, &err) != 0) {
		topo_mod_dprintf(mod, "fmri_str2nvl failed for %s=%" PRIx64
		    " (%s)", topo_node_name(node), topo_node_instance(node),
		    topo_strerror(err));
		goto done;
	}

	(void) topo_mod_nvalloc(mod, &pnvl, NV_UNIQUE_NAME);
	if (topo_fmri_getprop(thp, nvl, targ_group, targ_prop, NULL,
	    &pnvl, &err) != 0) {
		topo_mod_dprintf(mod, "getprop failed for %s=%" PRIx64
		    " (%s)",
		    topo_node_name(node), topo_node_instance(node),
		    topo_strerror(err));
		goto done;
	}

	/*
	 * We re-use the nvlist that we got back from topo_fmri_getprop since
	 * it already has the value and type information we're looking for.
	 */
	fnvlist_remove(pnvl, TOPO_PROP_VAL_NAME);
	fnvlist_add_string(pnvl, TOPO_PROP_VAL_NAME, pname);
	*out = pnvl;

done:
	return (err);
}

static ssize_t
fmri_bufsz(nvlist_t *nvl)
{
	nvlist_t **paths, *auth;
	uint_t nelem;
	char *type;
	ssize_t bufsz = 0;
	uint32_t start_phy = UINT32_MAX, end_phy = UINT32_MAX;

	if (nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &auth) != 0 ||
	    nvlist_lookup_string(auth, FM_FMRI_SAS_TYPE, &type) != 0)
		return (0);

	(void) nvlist_lookup_uint32(auth, FM_FMRI_SAS_START_PHY, &start_phy);
	(void) nvlist_lookup_uint32(auth, FM_FMRI_SAS_END_PHY, &end_phy);

	if (start_phy != UINT32_MAX && end_phy != UINT32_MAX) {
		bufsz += snprintf(NULL, 0, "sas://%s=%s:%s=%u:%s=%u",
		    FM_FMRI_SAS_TYPE, type, FM_FMRI_SAS_START_PHY, start_phy,
		    FM_FMRI_SAS_END_PHY, end_phy);
	} else {
		bufsz += snprintf(NULL, 0, "sas://%s=%s", FM_FMRI_SAS_TYPE,
		    type);
	}

	if (nvlist_lookup_nvlist_array(nvl, FM_FMRI_SAS_PATH, &paths,
	    &nelem) != 0) {
		return (0);
	}

	for (uint_t i = 0; i < nelem; i++) {
		char *sasname;
		uint64_t sasaddr;

		if (nvlist_lookup_string(paths[i], FM_FMRI_SAS_NAME,
		    &sasname) != 0 ||
		    nvlist_lookup_uint64(paths[i], FM_FMRI_SAS_ADDR,
		    &sasaddr) != 0) {
			return (0);
		}
		bufsz += snprintf(NULL, 0, "/%s=%" PRIx64 "", sasname,
		    sasaddr);
	}
	return (bufsz + 1);
}

static int
sas_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t scheme_vers;
	nvlist_t *outnvl;
	nvlist_t **paths, *auth;
	uint_t nelem;
	ssize_t bufsz, end = 0;
	char *buf, *type;
	uint32_t start_phy = UINT32_MAX, end_phy = UINT32_MAX;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(in, FM_FMRI_SAS_VERSION, &scheme_vers) != 0 ||
	    scheme_vers != FM_SAS_SCHEME_VERSION) {
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	/*
	 * Get size of buffer needed to hold the string representation of the
	 * FMRI.
	 */
	if ((bufsz = fmri_bufsz(in)) == 0) {
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));
	}

	if ((buf = topo_mod_zalloc(mod, bufsz)) == NULL) {
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	/*
	 * We've already successfully done these nvlist lookups in fmri_bufsz()
	 * so we don't worry about checking retvals this time around.
	 */
	(void) nvlist_lookup_nvlist(in, FM_FMRI_AUTHORITY, &auth);
	(void) nvlist_lookup_string(auth, FM_FMRI_SAS_TYPE, &type);
	(void) nvlist_lookup_uint32(auth, FM_FMRI_SAS_START_PHY, &start_phy);
	(void) nvlist_lookup_uint32(auth, FM_FMRI_SAS_END_PHY, &end_phy);
	(void) nvlist_lookup_nvlist_array(in, FM_FMRI_SAS_PATH, &paths,
	    &nelem);
	if (start_phy != UINT32_MAX && end_phy != UINT32_MAX)
		end += snprintf(buf, bufsz, "sas://%s=%s:%s=%u:%s=%u",
		    FM_FMRI_SAS_TYPE, type, FM_FMRI_SAS_START_PHY, start_phy,
		    FM_FMRI_SAS_END_PHY, end_phy);
	else
		end += snprintf(buf, bufsz, "sas://%s=%s", FM_FMRI_SAS_TYPE,
		    type);

	for (uint_t i = 0; i < nelem; i++) {
		char *sasname;
		uint64_t sasaddr;

		(void) nvlist_lookup_string(paths[i], FM_FMRI_SAS_NAME,
		    &sasname);
		(void) nvlist_lookup_uint64(paths[i], FM_FMRI_SAS_ADDR,
		    &sasaddr);
		end += snprintf(buf + end, (bufsz - end), "/%s=%" PRIx64 "",
		    sasname, sasaddr);
	}

	if (topo_mod_nvalloc(mod, &outnvl, NV_UNIQUE_NAME) != 0) {
		topo_mod_free(mod, buf, bufsz);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	if (nvlist_add_string(outnvl, "fmri-string", buf) != 0) {
		nvlist_free(outnvl);
		topo_mod_free(mod, buf, bufsz);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, buf, bufsz);
	*out = outnvl;

	return (0);
}

static int
sas_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	char *fmristr, *tmp = NULL, *lastpair;
	char *sasname, *auth_field, *path_start;
	nvlist_t *fmri = NULL, *auth = NULL, **sas_path = NULL;
	uint_t npairs = 0, i = 0, fmrilen, path_offset;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &fmristr) != 0)
		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));

	if (strncmp(fmristr, "sas://", 6) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0) {
		/* errno set */
		return (-1);
	}
	if (nvlist_add_string(fmri, FM_FMRI_SCHEME,
	    FM_FMRI_SCHEME_SAS) != 0 ||
	    nvlist_add_uint8(fmri, FM_FMRI_SAS_VERSION,
	    FM_SAS_SCHEME_VERSION) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	/*
	 * We need to make a copy of the fmri string because strtok will
	 * modify it.  We can't use topo_mod_strdup/strfree because
	 * topo_mod_strfree will end up leaking part of the string because
	 * of the NUL chars that strtok inserts - which will cause
	 * topo_mod_strfree to miscalculate the length of the string.  So we
	 * keep track of the length of the original string and use
	 * topo_mod_zalloc/topo_mod_free.
	 */
	fmrilen = strlen(fmristr);
	if ((tmp = topo_mod_zalloc(mod, fmrilen + 1)) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	(void) strncpy(tmp, fmristr, fmrilen);

	/*
	 * Find the offset of the "/" after the authority portion of the FMRI.
	 */
	if ((path_start = strchr(tmp + 6, '/')) == NULL) {
		(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
		topo_mod_free(mod, tmp, fmrilen + 1);
		goto err;
	}
	path_offset = path_start - tmp;

	/*
	 * Count the number of "=" chars after the "sas:///" portion of the
	 * FMRI to determine how big the sas-path array needs to be.
	 */
	(void) strtok_r(tmp + path_offset, "=", &lastpair);
	while (strtok_r(NULL, "=", &lastpair) != NULL)
		npairs++;

	if ((sas_path = topo_mod_zalloc(mod, npairs * sizeof (nvlist_t *))) ==
	    NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	/*
	 * Build the auth nvlist
	 */
	if (topo_mod_nvalloc(mod, &auth, NV_UNIQUE_NAME) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	(void) strncpy(tmp, fmristr, fmrilen);
	auth_field = tmp + 6;

	sasname = fmristr + path_offset + 1;

	while (auth_field < (tmp + path_offset)) {
		char *end, *auth_val;
		uint32_t phy;

		if ((end = strchr(auth_field, '=')) == NULL) {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}
		*end = '\0';
		auth_val = end + 1;

		if ((end = strchr(auth_val, ':')) == NULL &&
		    (end = strchr(auth_val, '/')) == NULL) {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}
		*end = '\0';

		if (strcmp(auth_field, FM_FMRI_SAS_TYPE) == 0) {
			(void) nvlist_add_string(auth, auth_field,
			    auth_val);
		} else if (strcmp(auth_field, FM_FMRI_SAS_START_PHY) == 0 ||
		    strcmp(auth_field, FM_FMRI_SAS_END_PHY) == 0) {

			phy = atoi(auth_val);
			(void) nvlist_add_uint32(auth, auth_field, phy);
		}
		auth_field = end + 1;
	}
	(void) nvlist_add_nvlist(fmri, FM_FMRI_AUTHORITY, auth);

	while (i < npairs) {
		nvlist_t *pathcomp;
		uint64_t sasaddr;
		char *end, *addrstr, *estr;

		if (topo_mod_nvalloc(mod, &pathcomp, NV_UNIQUE_NAME) != 0) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto err;
		}
		if ((end = strchr(sasname, '=')) == NULL) {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}
		*end = '\0';
		addrstr = end + 1;

		/*
		 * If this is the last pair, then addrstr will already be
		 * nul-terminated.
		 */
		if (i < (npairs - 1)) {
			if ((end = strchr(addrstr, '/')) == NULL) {
				(void) topo_mod_seterrno(mod,
				    EMOD_FMRI_MALFORM);
				goto err;
			}
			*end = '\0';
		}

		/*
		 * Convert addrstr to a uint64_t
		 */
		errno = 0;
		sasaddr = strtoull(addrstr, &estr, 16);
		if (errno != 0 || *estr != '\0') {
			(void) topo_mod_seterrno(mod, EMOD_FMRI_MALFORM);
			goto err;
		}

		/*
		 * Add both nvpairs to the nvlist and then add the nvlist to
		 * the sas-path nvlist array.
		 */
		if (nvlist_add_string(pathcomp, FM_FMRI_SAS_NAME, sasname) !=
		    0 ||
		    nvlist_add_uint64(pathcomp, FM_FMRI_SAS_ADDR, sasaddr) !=
		    0) {
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto err;
		}
		sas_path[i++] = pathcomp;
		sasname = end + 1;
	}
	if (nvlist_add_nvlist_array(fmri, FM_FMRI_SAS_PATH, sas_path,
	    npairs) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	*out = fmri;

	topo_mod_free(mod, tmp, fmrilen + 1);
	return (0);
err:
	topo_mod_dprintf(mod, "%s failed: %s", __func__,
	    topo_strerror(topo_mod_errno(mod)));
	if (sas_path != NULL) {
		for (i = 0; i < npairs; i++)
			nvlist_free(sas_path[i]);

		topo_mod_free(mod, sas_path, npairs * sizeof (nvlist_t *));
	}
	nvlist_free(fmri);
	topo_mod_free(mod, tmp, fmrilen + 1);
	return (-1);
}

/*
 * This method creates a sas-SCHEME FMRI that represents a pathnode.  This is
 * not intended to be called directly, but rather be called via
 * topo_mod_sasfmri()
 */
static int
sas_fmri_create(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	char *nodename;
	uint64_t nodeinst;
	nvlist_t *fmri = NULL, *args, *auth, *saspath[1], *pathcomp = NULL;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, TOPO_METH_FMRI_ARG_NAME, &nodename) !=
	    0 ||
	    nvlist_lookup_uint64(in, TOPO_METH_FMRI_ARG_INST, &nodeinst) !=
	    0 ||
	    nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NVL, &args) != 0 ||
	    nvlist_lookup_nvlist(args, TOPO_METH_FMRI_ARG_AUTH, &auth) != 0) {

		return (topo_mod_seterrno(mod, EMOD_METHOD_INVAL));
	}

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0) {
		/* errno set */
		return (-1);
	}

	if (nvlist_add_nvlist(fmri, FM_FMRI_AUTHORITY, auth) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_SAS) != 0 ||
	    nvlist_add_uint8(fmri, FM_FMRI_SAS_VERSION, FM_SAS_SCHEME_VERSION)
	    != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	if (topo_mod_nvalloc(mod, &pathcomp, NV_UNIQUE_NAME) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	if (nvlist_add_string(pathcomp, FM_FMRI_SAS_NAME, nodename) != 0 ||
	    nvlist_add_uint64(pathcomp, FM_FMRI_SAS_ADDR, nodeinst) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	saspath[0] = pathcomp;

	if (nvlist_add_nvlist_array(fmri, FM_FMRI_SAS_PATH, saspath, 1) != 0) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	*out = fmri;

	return (0);
err:
	topo_mod_dprintf(mod, "%s failed: %s", __func__,
	    topo_strerror(topo_mod_errno(mod)));
	nvlist_free(pathcomp);
	nvlist_free(fmri);
	return (-1);
}

/*
 * XXX - This will need to be refactored to support getting PHY counters out of
 * expander ports
 */
static int
sas_get_phy_err_counter(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *args, *pargs, *nvl, *fmri = NULL, *auth = NULL;
	char *pname, *hba_name = NULL;
	uint32_t hba_port, start_phy, end_phy;
	uint_t nphys;
	uint64_t *pvals = NULL;
	HBA_HANDLE handle = -1;
	SMHBA_PHYSTATISTICS phystats;
	SMHBA_SASPHYSTATISTICS sasphystats;
	int err, ret = -1;

	if (version > TOPO_METH_SAS_PHY_ERR_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	/*
	 * Now look for a private argument list to determine if the invoker is
	 * trying to do a set operation and if so, return an error as this
	 * method only supports get operations.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		topo_mod_dprintf(mod, "%s: set operation not suppported",
		    __func__);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0 ||
	    nvlist_lookup_string(args, "pname", &pname) != 0) {
		topo_mod_dprintf(mod, "%s: missing pname arg", __func__);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/*
	 * Get the HBA adapter name and port number off of the node, as we need
	 * these to lookup the PHY stats.
	 */
	if (topo_prop_get_string(node, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_ANAME, &hba_name, &err) != 0) {
		topo_mod_dprintf(mod, "%s: node missing %s prop", __func__,
		    TOPO_PROP_SASPORT_ANAME);
		return (topo_mod_seterrno(mod, err));
	}
	if (topo_prop_get_uint32(node, TOPO_PGROUP_SASPORT,
	    TOPO_PROP_SASPORT_APORT, &hba_port, &err) != 0) {
		topo_mod_dprintf(mod, "%s: node missing %s prop", __func__,
		    TOPO_PROP_SASPORT_APORT);
		(void) topo_mod_seterrno(mod, err);
		goto err;
	}

	/*
	 * Get the SAS FMRI and then lookup the authority portion in order to
	 * get the start and end PHY numbers.
	 */
	if (topo_node_resource(node, &fmri, &err) != 0) {
		(void) topo_mod_seterrno(mod, err);
		topo_mod_dprintf(mod, "%s: failed to get SAS FMRI", __func__);
		goto err;
	}
	if (nvlist_lookup_nvlist(fmri, FM_FMRI_AUTHORITY, &auth) != 0 ||
	    nvlist_lookup_uint32(auth, FM_FMRI_SAS_START_PHY, &start_phy) !=
	    0 ||
	    nvlist_lookup_uint32(auth, FM_FMRI_SAS_END_PHY, &end_phy) != 0) {
		topo_mod_dprintf(mod, "%s: malformed FMRI authority",
		    __func__);
		(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		goto err;
	}
	nphys = (end_phy - start_phy) + 1;

	/*
	 * Now that we know how many PHYs are on this port, allocate an array
	 * to hold the error counter value for each PHY.
	 */
	if ((pvals = topo_mod_zalloc(mod, sizeof (uint64_t) * nphys)) ==
	    NULL) {
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}

	/*
	 * Iterate through the PHYs on this port and retrieve the
	 * appropriate error counter value based on the property name.
	 */
	if ((handle = HBA_OpenAdapter(hba_name)) == 0) {
		topo_mod_dprintf(mod, "%s: failed to open adapter: %s",
		__func__, hba_name);
		(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto err;
	}
	for (uint_t phy = 0; phy < nphys; phy++) {

		(void) memset(&phystats, 0, sizeof (SMHBA_PHYSTATISTICS));
		(void) memset(&sasphystats, 0, sizeof (SMHBA_SASPHYSTATISTICS));
		phystats.SASPhyStatistics = &sasphystats;

		ret = SMHBA_GetPhyStatistics(handle, hba_port, phy, &phystats);
		if (ret != HBA_STATUS_OK) {
			topo_mod_dprintf(mod, "%s: failed to get HBA PHY stats "
			    "for PORT %u PHY %u (ret=%u)", __func__, hba_port,
			    phy, ret);
			(void) topo_mod_seterrno(mod, EMOD_UNKNOWN);
			goto err;
		}
		if (strcmp(pname, TOPO_PROP_SASPORT_INV_DWORD) == 0)
			pvals[phy] = phystats.
			    SASPhyStatistics->InvalidDwordCount;
		else if (strcmp(pname, TOPO_PROP_SASPORT_RUN_DISP) == 0)
			pvals[phy] = phystats.
			    SASPhyStatistics->RunningDisparityErrorCount;
		else if (strcmp(pname, TOPO_PROP_SASPORT_LOSS_SYNC) == 0)
			pvals[phy] = phystats.
			    SASPhyStatistics->LossofDwordSyncCount;
		else if (strcmp(pname, TOPO_PROP_SASPORT_RESET_PROB) == 0)
			pvals[phy] = phystats.
			    SASPhyStatistics->PhyResetProblemCount;
	}

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, pname) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT64_ARRAY)
	    != 0 ||
	    nvlist_add_uint64_array(nvl, TOPO_PROP_VAL_VAL, pvals, nphys)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist");
		nvlist_free(nvl);
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto err;
	}
	*out = nvl;
	ret = 0;
err:
	if (handle != -1)
		HBA_CloseAdapter(handle);
	nvlist_free(fmri);
	topo_mod_free(mod, pvals, sizeof (uint64_t) * nphys);
	topo_mod_strfree(mod, hba_name);
	return (ret);
}
